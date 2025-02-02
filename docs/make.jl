using Documenter, HTTP, Sockets, URIs

"""
Loops through the files in the examples folder and adds them (with any header comments) to the examples.md
markdown file. 
"""
function generateExamples()
    f = IOBuffer()
    write(
        f,
        "```@meta
    # NOTE this file is autogenerated, do not edit examples.md directly. To make an example, upload the .jl file to the examples folder. Header comments may be included at the top of the file using \"\"\" syntax
``` ",
    )
    write(f, "\n")
    write(f, "# Examples")
    write(
        f,
        "\nSome examples that may prove potentially useful for those using 
`HTTP.jl`. The code for these examples can also be found on Github
 in the `docs/examples` folder.",
    )
    for (root, dirs, files) in walkdir(joinpath(@__DIR__, "examples"))
        #set order of files so simple is first, and Readme examples are last
        temp = files[1]
        files[findfirst(isequal("simple_server.jl"), files)] = temp
        files[1] = "simple_server.jl"
        temp = files[2]
        files[findfirst(isequal("cors_server.jl"), files)] = temp
        files[2] = "cors_server.jl"
        temp = files[length(files)]
        files[findfirst(isequal("readme_examples.jl"), files)] = temp
        files[length(files)] = "readme_examples.jl"

        for file in files
            println(file)
            #extract title from example
            write(f, "\n")
            title = file
            title = replace(title, "_" => " ")
            title = replace(title, ".jl" => "")
            title = titlecase(title)
            title = "## " * title * "\n"
            write(f, title)
            #open each file and read contents
            opened = open(joinpath(@__DIR__, "examples/") * file)
            lines = readlines(opened, keep = true)
            index = 1
            #find doc string intro if exists
            if "\"\"\"\n" in lines
                index = findall(isequal("\"\"\"\n"), lines)[2]
                print(index)
                for i = 2:index-1
                    write(f, lines[i])
                end
                lines = lines[index+1:end]
            end

            write(f, "```julia")
            write(f, "\n")
            for line in lines
                write(f, line)
            end
            write(f, "\n")
            write(f, "```")
            close(opened)
        end
    end
    file = joinpath(@__DIR__, "src/examples.md")
    current_content = isfile(file) ? read(file, String) : ""
    updated_content = String(take!(f))
    # Only update content if something changed so that the file watcher in
    # LiveServer.jl isn't triggering itself when running make.jl.
    if updated_content != current_content
        write(file, updated_content)
    end
end

generateExamples()

makedocs(
    # modules = [HTTP],
    sitename = "HTTP.jl",
    pages = [
        "Home" => "index.md",
        "client.md",
        "server.md",
        "websockets.md",
        "reference.md",
        "examples.md",
    ],
)

deploydocs(
    repo = "github.com/JuliaWeb/HTTP.jl.git",
    push_preview = true,
)
