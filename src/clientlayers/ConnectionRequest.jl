module ConnectionRequest

using URIs, Sockets, Base64, ConcurrentUtilities, ExceptionUnwrapping
import MbedTLS
import OpenSSL
using ..Messages, ..IOExtras, ..Connections, ..Streams, ..Exceptions
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

const CLOSE_IMMEDIATELY = Ref{Bool}(false)

"""
    connectionlayer(handler) -> handler

Retrieve an `IO` connection from the Connections.

Close the connection if the request throws an exception.
Otherwise leave it open so that it can be reused.
"""
function connectionlayer(handler)
    return function connections(req; proxy=getproxy(req.url.scheme, req.url.host), socket_type::Type=TCPSocket, socket_type_tls::Union{Nothing, Type}=nothing, readtimeout::Int=0, connect_timeout::Int=30, logerrors::Bool=false, logtag=nothing, closeimmediately::Bool=CLOSE_IMMEDIATELY[], kw...)
        local io, stream
        if proxy !== nothing
            target_url = req.url
            url = URI(proxy)
            if target_url.scheme == "http" && url.scheme == "http"
                req.target = string(target_url)
            end

            userinfo = unescapeuri(url.userinfo)
            if !isempty(userinfo) && !hasheader(req.headers, "Proxy-Authorization")
                @debug "Adding Proxy-Authorization: Basic header."
                setheader(req.headers, "Proxy-Authorization" => "Basic $(base64encode(userinfo))")
            end
        else
            url = target_url = req.url
        end

        connect_timeout = connect_timeout == 0 && readtimeout > 0 ? readtimeout : connect_timeout
        IOType = sockettype(url, socket_type, socket_type_tls, get(kw, :sslconfig, nothing))
        start_time = time()
        try
            io = newconnection(IOType, url.host, url.port; readtimeout=readtimeout, connect_timeout=connect_timeout, kw...)
        catch e
            if logerrors
                @error current_exceptions_to_string() type=Symbol("HTTP.ConnectError") method=req.method url=req.url context=req.context logtag=logtag
            end
            req.context[:connect_errors] = get(req.context, :connect_errors, 0) + 1
            throw(ConnectError(string(url), e))
        finally
            req.context[:connect_duration_ms] = get(req.context, :connect_duration_ms, 0.0) +  (time() - start_time) * 1000
        end

        shouldreuse = !(target_url.scheme in ("ws", "wss")) && !closeimmediately
        try
            if proxy !== nothing && target_url.scheme in ("https", "http", "wss", "ws")
                shouldreuse = false
                # tunnel request
                if target_url.scheme in ("https", "wss")
                    target_url = URI(target_url, port=443)
                elseif target_url.scheme in ("http", "ws") && target_url.port == ""
                    target_url = URI(target_url, port=80) # if there is no port info, connect_tunnel will fail
                end
                connect_tun = (url.scheme == "socks5h") ? connect_tunnel_socks5 : connect_tunnel
                r = if readtimeout > 0
                    # try_with_timeout(readtimeout) do _
                    try_with_timeout(() -> shouldtimeout(io, readtimeout), readtimeout, () -> close(io)) do
                        connect_tun(io, target_url, url, req)
                    end
                else
                    connect_tun(io, target_url, url, req)
                end
                if r.status != 200
                    close(io)
                    return r
                end
                if target_url.scheme in ("https", "wss")
                    InnerIOType = sockettype(target_url, socket_type, socket_type_tls, get(kw, :sslconfig, nothing))
                    io = Connections.sslupgrade(InnerIOType, io, target_url.host; readtimeout=readtimeout, kw...)
                end
                req.headers = filter(x->x.first != "Proxy-Authorization", req.headers)
            end

            stream = Stream(req.response, io)
            return handler(stream; readtimeout=readtimeout, logerrors=logerrors, logtag=logtag, kw...)
        catch e
            shouldreuse = false
            # manually unwrap CompositeException since it's not defined as a "wrapper" exception by ExceptionUnwrapping
            while e isa CompositeException
                e = e.exceptions[1]
            end
            root_err = ExceptionUnwrapping.unwrap_exception_to_root(e)
            # don't log if it's an HTTPError since we should have already logged it
            if logerrors && root_err isa StatusError
                @error current_exceptions_to_string() type=Symbol("HTTP.StatusError") method=req.method url=req.url context=req.context logtag=logtag
            end
            if logerrors && !ExceptionUnwrapping.has_wrapped_exception(e, HTTPError)
                @error current_exceptions_to_string() type=Symbol("HTTP.ConnectionRequest") method=req.method url=req.url context=req.context logtag=logtag
            end
            @debug "❗️  ConnectionLayer $root_err. Closing: $io"
            if @isdefined(stream) && stream.nwritten == -1
                # we didn't write anything, so don't need to worry about
                # idempotency of the request
                req.context[:nothingwritten] = true
            end
            root_err isa HTTPError || throw(RequestError(req, root_err))
            throw(root_err)
        finally
            releaseconnection(io, shouldreuse; kw...)
            if !shouldreuse
                @try Base.IOError close(io)
            end
        end
    end
end

function sockettype(url::URI, socket_type_tcp, socket_type_tls, sslconfig)
    if url.scheme in ("wss", "https")
        tls_socket_type(socket_type_tls, sslconfig)
    else
        socket_type_tcp
    end
end

"""
    tls_socket_type(socket_type_tls, sslconfig)::Type

Find the best TLS socket type, given the values of these keyword arguments.

If both are `nothing` then we use the global default: `HTTP.SOCKET_TYPE_TLS[]`.
If both are not `nothing` then they must agree:
`sslconfig` must be of the right type to configure `socket_type_tls` or we throw an `ArgumentError`.
"""
function tls_socket_type(socket_type_tls::Union{Nothing, Type},
                         sslconfig::Union{Nothing, MbedTLS.SSLConfig, OpenSSL.SSLContext}
                         )::Type

    socket_type_matching_sslconfig =
        if sslconfig isa MbedTLS.SSLConfig
            MbedTLS.SSLContext
        elseif sslconfig isa OpenSSL.SSLContext
            OpenSSL.SSLStream
        else
            nothing
        end

    if socket_type_tls === socket_type_matching_sslconfig
        # Use the global default TLS socket if they're both nothing, or use
        # what they both specify if they're not nothing.
        isnothing(socket_type_tls) ? SOCKET_TYPE_TLS[] : socket_type_tls
    # If either is nothing, use the other one.
    elseif isnothing(socket_type_tls)
        socket_type_matching_sslconfig
    elseif isnothing(socket_type_matching_sslconfig)
        socket_type_tls
    else
        # If they specify contradictory types, throw an error.
        # Error thrown in noinline closure to avoid speed penalty in common case
        @noinline function err(socket_type_tls, sslconfig)
            msg = """
                Incompatible values for keyword args `socket_type_tls` and `sslconfig`:
                    socket_type_tls=$socket_type_tls
                    typeof(sslconfig)=$(typeof(sslconfig))

                Make them match or provide only one of them.
                - the socket type MbedTLS.SSLContext is configured by MbedTLS.SSLConfig
                - the socket type OpenSSL.SSLStream is configured by OpenSSL.SSLContext"""
            throw(ArgumentError(msg))
        end
        err(socket_type_tls, sslconfig)
    end
end

function connect_tunnel(io, target_url, url, req)
    target = "$(URIs.hoststring(target_url.host)):$(target_url.port)"
    @debug "📡  CONNECT HTTPS tunnel to $target"
    headers = Dict("Host" => target)
    if (auth = header(req, "Proxy-Authorization"); !isempty(auth))
        headers["Proxy-Authorization"] = auth
    end
    request = Request("CONNECT", target, headers)
    # @debug "connect_tunnel: writing headers"
    writeheaders(io, request)
    # @debug "connect_tunnel: reading headers"
    readheaders(io, request.response)
    # @debug "connect_tunnel: done reading headers"
    return request.response
end

function connect_tunnel_socks5(io, target_url, url, req)
    chain = reverse([Tuple(split(p, ':')) for p in split(url.path, '/') if !isempty(p)])
    push!(chain, (target_url.host, target_url.port))

    target = "$(URIs.hoststring(chain[end][1])):$(chain[end][2])"
    @debugv 1 "📡  CONNECT SOCKS5 tunnel to $target, chain length: $(length(chain))"

    SUCCEEDED = 0x00
    VER = 0x05
    NO_AUTH_REQ = 0x00
    CMD_CONNECT = 0x01
    RSV = 0x00
    ATYP_IPV4 = 0x01
    ATYP_DOMAINNAME = 0x03
    ATYP_IPV6 = 0x04

    for (host, port) in chain
        # auth
        NMETHODS = 0x01
        METHODS = [NO_AUTH_REQ]
        write(io, vcat(VER, NMETHODS, METHODS))
        ver = read(io, UInt8)
        method = read(io, UInt8)
        @assert ver == VER
        @assert method == NO_AUTH_REQ

        # request
        CMD = CMD_CONNECT
        DST_PORT = hton(UInt16(parse(UInt16, port)))
        ATYP =  ATYP_DOMAINNAME
        DST_ADDR = vcat([UInt8(length(host))], map(UInt8, collect(host)))
        bio = IOBuffer()
        write(bio, vcat(VER, CMD, RSV, ATYP))
        write(bio, DST_ADDR)
        write(bio, DST_PORT)
        write(io, take!(bio))

        ver = read(io, UInt8); @assert ver == VER
        rep = read(io, UInt8); @assert rep == SUCCEEDED "rep: $rep"
        rsv = read(io, UInt8); @assert rsv == 0x00
        atyp = read(io, UInt8); @assert atyp == ATYP_IPV4
        bnd_addr = [Int(read(io, UInt8)) for _ in 1:4]
        bnd_port = Int(ntoh(read(io, UInt16)))
    end

    Response(200)
end

end # module ConnectionRequest
