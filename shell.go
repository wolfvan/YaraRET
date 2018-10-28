/*
Open Source Initiative OSI - The MIT License (MIT):Licensing
The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http:
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package main

import (
	"fmt"
	"github.com/abiosoft/ishell"
	"strconv"
)

func runShell(rawdisk string) {
	
	
	shell := ishell.New()
	shell.AddCmd(&ishell.Cmd{
		Name: "start",
		Help: "start filetype",
		Func: func(c *ishell.Context) {
			
			

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("start " + command)

			}
			if len(c.Args) > 0 {
				startCmd(c.Args, rawdisk)

			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "supported",
		Help: "list supported filetypes",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("start " + command)

			}
			if len(c.Args) > 0 {
				startCmd(c.Args, rawdisk)

			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "~",
		Help: "~ radare2Command",
		Func: func(c *ishell.Context) {
			var mybool bool
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("yara " + command)

			}
			if len(c.Args) > 0 {
				radareCmd2(c.Args, rawdisk, strconv.Itoa(int(sliceSet[0].OffsetHeader)))
			} else {
				if len(sliceSet) < 2 {
					for _, elem := range sliceSet {
						rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)
					}
					mybool = radareSession(rawdisk)
					fmt.Println(mybool)
				} else {

					fmt.Println("I need more arguments :(")
				}
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "yara",
		Help: "yara yaraRule",
		Func: func(c *ishell.Context) {
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("yara " + command)

			}
			if len(c.Args) > 0 {
				if c.Args[0] == "+" {
					yaraCmd(c.Args[1])
				} else {
					fmt.Println("[+] Running a fast scan")
					yaraLightCmd(c.Args, rawdisk)
				}
			} else {

				fmt.Println("I need more arguments :(")
			}

		},
	})


	shell.AddCmd(&ishell.Cmd{
		Name: "resume",
		Help: "resume of all data",
		Func: func(c *ishell.Context) {
			
			

			var allRules string
			for _, element := range sliceNewResults {
				allRules = allRules + element.Rule + " "

			}
			wordCount(allRules)
		},
	})


	shell.AddCmd(&ishell.Cmd{
		Name: "unset",
		Help: "unset index/filetype",
		Func: func(c *ishell.Context) {
			
			

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("unset " + command)

			}
			if len(c.Args) > 0 {
				unsetCmd(c.Args, rawdisk)

			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "run",
		Help: "run script",
		Func: func(c *ishell.Context) {
			
			

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("run " + command)

			}
			if len(c.Args) > 0 {
				runCmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "save",
		Help: "save outputfile",
		Func: func(c *ishell.Context) {
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("save " + command)

			}

			saveCmd(c.Args, rawdisk)

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "open",
		Help: "open file",
		Func: func(c *ishell.Context) {
			
			

			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("open " + command)

			}
			if len(c.Args) > 0 {
				openCmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "dump",
		Help: "dumps the selected files",
		Func: func(c *ishell.Context) {
	
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("dump " + command)

			}

			dumpCmd(rawdisk)

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "upload",
		Help: "upload host port",
		Func: func(c *ishell.Context) {
			
		if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("dump " + command)

			}

			uploadCmd(c.Args, rawdisk)

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "vti",
		Help: "vti",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("vti " + command)

			}

			if len(c.Args)>0{
				switch option := c.Args[0]; option {

				case "key":
					vtiAPI = c.Args[1]
				default:
					vtiCmd(c.Args, rawdisk)
				}
			}else{
				fmt.Println("[!] Please provide arguments to this call")
				

			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "show",
		Help: "show filetype",
		Func: func(c *ishell.Context) {
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("show " + command)

			}
			if len(c.Args) > 0 {
				showCmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "var",
		Help: "var variable",
		Func: func(c *ishell.Context) {
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("var " + command)

			}
			if len(c.Args) > 0 {
				varCmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "lastitem",
		Help: "lastitem",
		Func: func(c *ishell.Context) {
			
			

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("vti " + command)

			}
			lastItemStruct()
			

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "ioc",
		Help: "ioc file",
		Func: func(c *ishell.Context) {
			
			
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("ioc " + command)

			}
			if len(c.Args) > 0 {
				searchOpenIOCCmd2(rawdisk, c.Args[0])
				
				
			} else {
				fmt.Println("I need more arguments :(")
			}
			

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "output",
		Help: "output nameFile",
		Func: func(c *ishell.Context) {
			
			
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("output " + command)

			}
			if len(c.Args) > 0 {
				outputCmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "set",
		Help: "selects an index or filetype",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("set " + command)

			}
			if len(c.Args) > 0 {
				set2Cmd(c.Args, rawdisk)
			} else {
				fmt.Println("I need more arguments :(")
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "hash",
		Help: "hash /path",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("hash " + command)

			}
			hashCmd(c.Args, rawdisk)

		},
	})


	shell.AddCmd(&ishell.Cmd{
		Name: "ssdeep",
		Help: "ssdeep set of file/s",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("ssdeep " + command)

			}
			ssdeepCmd(c.Args, rawdisk)

		},
	})


	shell.AddCmd(&ishell.Cmd{
		Name: "tag",
		Help: "Put a tag in selected files",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("rawdisk " + command)

			}
	
			if len(c.Args)>0 && len(c.Args)<2{
				putTag(c.Args[0])

				
			}
			

		},
	})


	shell.AddCmd(&ishell.Cmd{
		Name: "entropy",
		Help: "entropy index/filetype",
		Func: func(c *ishell.Context) {

			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("entropy " + command)

			}

			entropyCmd2(c.Args, rawdisk)

		},
	})

	
	
	
	
	
	
	
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

	

	
	
	
	
	
	

	shell.AddCmd(&ishell.Cmd{
		Name: "yaraforensics",
		Help: "yaraforensics",
		Func: func(c *ishell.Context) {
			
			
			if verbose == true {

				command := ""
				for _, b := range c.Args {

					command += b + " "
				}
				saveCommand("yaraforensics " + command)

			}
			yaraforensicsCmd(c.Args, rawdisk)

		},
	})

	
	shell.Run()
}
