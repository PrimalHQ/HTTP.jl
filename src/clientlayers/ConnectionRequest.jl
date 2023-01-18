module ConnectionRequest

using URIs, Sockets, Base64, LoggingExtras
using MbedTLS: SSLContext, SSLConfig
using OpenSSL: SSLStream
using ..Messages, ..IOExtras, ..ConnectionPool, ..Streams, ..Exceptions
import ..SOCKET_TYPE_TLS

islocalhost(host::AbstractString) = host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0000:0000:0000:0000:0000:0000:0000:0001" || host == "0:0:0:0:0:0:0:1"

# hasdotsuffix reports whether s ends in "."+suffix.
hasdotsuffix(s, suffix) = endswith(s, "." * suffix)

function isnoproxy(host::AbstractString)
    for x in NO_PROXY
        (hasdotsuffix(host, x) || (host == x)) && return true
    end
    return false
end

const NO_PROXY = String[]

function __init__()
    # check for no_proxy environment variable
    if haskey(ENV, "no_proxy")
        for x in split(ENV["no_proxy"], ","; keepempty=false)
            push!(NO_PROXY, startswith(x, ".") ? x[2:end] : x)
        end
    end
    return
end

function getproxy(scheme, host)
    (isnoproxy(host) || islocalhost(host)) && return nothing
    if scheme == "http" && (p = get(ENV, "http_proxy", ""); !isempty(p))
        return p
    elseif scheme == "http" && (p = get(ENV, "HTTP_PROXY", ""); !isempty(p))
        return p
    elseif scheme == "https" && (p = get(ENV, "https_proxy", ""); !isempty(p))
        return p
    elseif scheme == "https" && (p = get(ENV, "HTTPS_PROXY", ""); !isempty(p))
        return p
    elseif scheme == "ws" && (p = get(ENV, "HTTP_PROXY", ""); !isempty(p))
        return p
    elseif scheme == "wss" && (p = get(ENV, "HTTPS_PROXY", ""); !isempty(p))
        return p
    end
    return nothing
end

export connectionlayer

"""
    connectionlayer(handler) -> handler

Retrieve an `IO` connection from the ConnectionPool.

Close the connection if the request throws an exception.
Otherwise leave it open so that it can be reused.
"""
function connectionlayer(handler)
    return function(req; proxy=getproxy(req.url.scheme, req.url.host), socket_type::Type=TCPSocket, socket_type_tls::Type=SOCKET_TYPE_TLS[], readtimeout::Int=0, kw...)
        local io, stream
        if proxy !== nothing
            target_url = req.url
            url = URI(proxy)
            if target_url.scheme == "http"
                req.target = string(target_url)
            end

            userinfo = unescapeuri(url.userinfo)
            if !isempty(userinfo) && !hasheader(req.headers, "Proxy-Authorization")
                @debugv 1 "Adding Proxy-Authorization: Basic header."
                setheader(req.headers, "Proxy-Authorization" => "Basic $(base64encode(userinfo))")
            end
        else
            url = target_url = req.url
        end

        IOType = sockettype(url, socket_type, socket_type_tls)
        try
            io = newconnection(IOType, url.host, url.port; readtimeout=readtimeout, kw...)
        catch e
            throw(ConnectError(string(url), e))
        end

        shouldreuse = !(target_url.scheme in ("ws", "wss"))
        try
            if proxy !== nothing && target_url.scheme in ("https", "wss", "ws")
                shouldreuse = false
                # tunnel request
                if target_url.scheme in ("https", "wss")
                    target_url = URI(target_url, port=443)
                elseif target_url.scheme in ("ws", ) && target_url.port == ""
                    target_url = URI(target_url, port=80) # if there is no port info, connect_tunnel will fail
                end
                connect_tun = (url.scheme == "socks5h") ? connect_tunnel_socks5 : connect_tunnel
                r = if readtimeout > 0
                    try_with_timeout(() -> shouldtimeout(io, readtimeout), readtimeout, () -> close(io)) do
                        connect_tun(io, target_url, req)
                    end
                else
                    connect_tun(io, target_url, req)
                end
                if r.status != 200
                    close(io)
                    return r
                end
                if target_url.scheme in ("https", "wss")
                    io = ConnectionPool.sslupgrade(socket_type_tls, io, target_url.host; readtimeout=readtimeout, kw...)
                end
                req.headers = filter(x->x.first != "Proxy-Authorization", req.headers)
            end

            stream = Stream(req.response, io)
            return handler(stream; readtimeout=readtimeout, kw...)
        catch e
            @debugv 1 "❗️  ConnectionLayer $e. Closing: $io"
            shouldreuse = false
            @try Base.IOError close(io)
            if @isdefined(stream) && stream.nwritten == -1
                # we didn't write anything, so don't need to worry about
                # idempotency of the request
                req.context[:nothingwritten] = true
            end
            e isa HTTPError || throw(RequestError(req, e))
            rethrow()
        finally
            releaseconnection(io, shouldreuse)
            if !shouldreuse
                @try Base.IOError close(io)
            end
        end
    end
end

sockettype(url::URI, tcp, tls) = url.scheme in ("wss", "https") ? tls : tcp

function connect_tunnel(io, target_url, req)
    target = "$(URIs.hoststring(target_url.host)):$(target_url.port)"
    @debugv 1 "📡  CONNECT HTTPS tunnel to $target"
    headers = Dict("Host" => target)
    if (auth = header(req, "Proxy-Authorization"); !isempty(auth))
        headers["Proxy-Authorization"] = auth
    end
    request = Request("CONNECT", target, headers)
    # @debugv 2 "connect_tunnel: writing headers"
    writeheaders(io, request)
    # @debugv 2 "connect_tunnel: reading headers"
    readheaders(io, request.response)
    # @debugv 2 "connect_tunnel: done reading headers"
    return request.response
end

function connect_tunnel_socks5(io, target_url, req)
    target = "$(URIs.hoststring(target_url.host)):$(target_url.port)"
    @debugv 1 "📡  CONNECT SOCKS5 tunnel to $target"

    SUCCEEDED = 0x00

    # auth
    VER = 0x05
    NMETHODS = 0x01
    NO_AUTH_REQ = 0x00
    METHODS = [NO_AUTH_REQ]
    write(io, vcat(VER, NMETHODS, METHODS))
    ver = read(io, UInt8)
    method = read(io, UInt8)
    @assert ver == VER
    @assert method == NO_AUTH_REQ

    # request
    CMD_CONNECT = 0x01
    CMD = CMD_CONNECT
    RSV = 0x00
    ATYP_IPV4 = 0x01
    ATYP_DOMAINNAME = 0x03
    ATYP_IPV6 = 0x04
    ATYP = ATYP_DOMAINNAME
    DST_ADDR = vcat([UInt8(length(target_url.host))], map(UInt8, collect(target_url.host)))
    DST_PORT = hton(UInt16(parse(UInt16, target_url.port)))
    bio = IOBuffer()
    write(bio, vcat(VER, CMD, RSV, ATYP))
    write(bio, DST_ADDR)
    write(bio, DST_PORT)
    write(io, take!(bio))

    ver = read(io, UInt8); @assert ver == VER
    rep = read(io, UInt8); @assert rep == SUCCEEDED "rep: $rep"
    rsv = read(io, UInt8); @assert rsv == 0x00
    atyp = read(io, UInt8); @assert atyp == ATYP_IPV4
    # bnd_addr_len = read(io, UInt8)
    # @assert bnd_addr_len < 1000
    # @show bnd_addr = String(read(io, bnd_addr_len))
    bnd_addr_port = [read(io, UInt8) for _ in 1:6]

    Response(200)
end

end # module ConnectionRequest
