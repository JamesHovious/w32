About w32
==========

w32 is a wrapper of windows apis for the Go Programming Language.

It wraps win32 apis to "Go style" to make them easier to use.

## Notes
This library was originally a clone of [AllenDang/w32](https://github.com/AllenDang/w32). At the time the repo appeared to be abandoned. Since I made this clone though the original repo picked up development again, but I decided to take this in a slightly different direction. 

This library aims to mirror the win32 api and other Windows system dlls, without additional abstractions built on top of it. It attempts to be as organized/documented as possible. 

This mirror has some of my own additions plus updates from other forks of the original project. I've attempted to document where I've pulled code from someone else. 

I add new API functions in if my current project needs them. If your project needs a particular function please submit a PR or issue. I also add in additional functions as I see other forks, or Go libraries that have them.


Example
=====
```
package main

import (
	"github.com/JamesHovious/w32"
)

func main() {
	w32.MessageBox(0, "Hello World!", "Hello, World!", 0)
}
```

For more examples, look at the example folder.

Setup
=====

1. [Install Go](https://golang.org/dl/). I recommend 32bit aka i386 due to GCC 64bit issues on windows.
2. Get a GCC compiler. I recommend the [WinBuilds version](http://win-builds.org/doku.php/download_and_installation_from_windows).
3. From the command line, type `go get github.com/JamesHovious/w32`
4. Create a new file, and try the example above.

Contribute
==========

Contributions in form of design, code, documentation, bug reporting or other ways you see fit are very welcome.

Thank You!
