/*
Open Source Initiative OSI - The MIT License (MIT):Licensing
The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>
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
	//      "encoding/gob"
	//      "net"
	"bufio"
	"github.com/radare/r2pipe-go"
	"strconv"
	"strings"
	"os"
)



func searchRadare(resultsToT []result, rawdisk string, filetype string, maxsize string) {
	var rulesMatched []string
	//magicRules := magicPath+filetype+".yar"
	//fmt.Println(magicRules)
	//fmt.Println(len(resultsToT))
	//defer r2p4.Close()

	indexNum := 0
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()
	for _, elem := range resultsToT {
		//fmt.Println(elem)
		//fmt.Println(elem.offset)
		if stringInSlice(elem.rule, rulesMatched) == false {
			rulesMatched = append(rulesMatched, elem.rule)
			indexNum += 1
			pathFile := "/tmp/"
			nameFile := elem.rule + strconv.Itoa(int(indexNum))
			//fmt.Println(pathFile)
			//fmt.Println(nameFile)
			//fmt.Println(elem.offset)
			disasm, err := r2p.Cmd("s " + strconv.Itoa(int(elem.offset)))
			if err != nil {
				print("ERROR: ", err)
			} else {
				print(disasm, "")
			}
			disasm2, err := r2p.Cmd("s -" + maxsize)
			if err != nil {
				print("ERROR: ", err)
			} else {
				print(disasm2, "")
			}
			maxsizeInt, err := strconv.ParseFloat(maxsize, 64)
			if err != nil {
			}
			//fmt.Println(maxsizeInt)
			//maxsize2 := maxsizeInt*2
			disasm3, err := r2p.Cmd("wtf " + pathFile + nameFile + " " + strconv.FormatFloat(maxsizeInt*2, 'f', 6, 64))
			if err != nil {
				print("ERROR: ", err)
			} else {
				print(disasm3, "")
			}

			resultsMagic := searchYara(pathFile+nameFile, "./magicrules/magicrules_header.yar")
			//fmt.Println(resultsMagic)

			for _, elem2 := range resultsMagic {
				//fmt.Println(pathFile+nameFile)
				r2p2, err := r2pipe.NewPipe(pathFile + nameFile)
				if err != nil {
					print("ERROR: ", err)
				}

				defer r2p2.Close()

				disasm4, err := r2p2.Cmd("s " + strconv.Itoa(int(elem2.offset)))
				if err != nil {
					print("ERROR: ", err)
					print(disasm4, "")
				} else {
					disasm4 := ""
					print(disasm4, "")
					///fmt.Println()
				}

				//hexAddr := strings.Split(disasm99," ")[1]

				//fmt.Println(hexAddr)

				disasm98, err := r2p2.Cmd("b " + maxsize)
				if err != nil {
					print("ERROR: ", err)
				} else {
					print(disasm98, "")
				}

				//disasm5, err := r2p2.Cmd("wtf! "+pathFile+nameFile+"_2"+" "+strconv.FormatFloat(maxsizeInt, 'f', 6, 64))
				disasm5, err := r2p2.Cmd("wtf! " + pathFile + nameFile + "_2")
				//disasm5, err := r2p2.Cmd("wtf @"+hexAddr)
				if err != nil {
					print("ERROR: ", err)
				} else {
					disasm5 = ""
					print(disasm5, "")
				}

				r2p2.Close()
				//fmt.Println("open new file")
				//r2p3, err := r2pipe.NewPipe(pathFile+nameFile+"_2")
				r2p4, err := r2pipe.NewPipe(pathFile + nameFile + "_2")
				if err != nil {
					print("ERROR: ", err)
					fmt.Println("can't open")
				}
				//defer r2p4.Close()
				//fmt.Println("after open")

				disasm96, err := r2p4.Cmd("s 0x0")
				if err != nil {
					print("ERROR: ", err)
				} else {
					disasm96 = ""
					print(disasm96, "")
				}

				disasm6, err := r2p4.Cmd("iZ")
				if err != nil {
					print("ERROR: ", err)
				} else {
					disasm6 := ""
					print(disasm6, "")
				}

				//fmt.Println("calc size")
				disasm8, err := r2p4.Cmd("wtf " + "Exported_" + nameFile + " " + disasm6)
				if err != nil {
					print("ERROR: ", err)
				} else {
					disasm8 = ""
					print(disasm8, "")
				}

				if strings.Contains(elem.rule, "pe") {
					getSizePe("Exported_" + nameFile)
				}

				fmt.Println("\n")
				fmt.Println("[+] Dumped file:\n\t[-] Rule: " + elem.rule + "\n\t[-] Name: " + "Exported_" + nameFile + "\n\t[-] FileType: " + strings.Split(elem2.rule, "_")[0])
			}

		}

		//fmt.Println(nameFile)

	}
}



func runHashReturn(rawdisk string, elem newResult) string {
	//yarafile := "./magicrules/magicrules_footer_index.yar"
	//var lastResult result

	//var newR newResult
	//fmt.Println(sliceNewResults)
	a := getHashReturn(rawdisk, elem.OffsetHeader, elem.Size)

	//fmt.Println(resultsHash)

	//fmt.Println(sliceNewResults)

	return a

}


func getHashReturn(rawdisk string, header uint64, block uint64) string {
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()

	// tener en cuenta que el match se hace al princpio de la cadena y
	//tenemos que saber cuantos bytes faltan hasta el último para generar correctamente un bloque
	disasm, err := r2p.Cmd("b " + strconv.Itoa(int(block)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}

	disasm2, err := r2p.Cmd("s " + strconv.Itoa(int(header)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm2, "")
	}

	disasm3, err := r2p.Cmd("ph md5")
	if err != nil {
		print("ERROR: ", err)
	} else {
	}
	return disasm3
}



func getHashSelected(rawdisk string, header uint64, block uint64) string {
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()

	// tener en cuenta que el match se hace al princpio de la cadena y
	//tenemos que saber cuantos bytes faltan hasta el último para generar correctamente un bloque
	disasm, err := r2p.Cmd("b " + strconv.Itoa(int(block)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}

	disasm2, err := r2p.Cmd("s "+strconv.Itoa(int(header)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm2, "")
	}




	disasm3, err := r2p.Cmd("ph md5")
	if err != nil {
		print("ERROR: ", err)
	} else {
	}
	return disasm3
}



func getHash(rawdisk string, header uint64, block uint64) {
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()

	// tener en cuenta que el match se hace al princpio de la cadena y
	//tenemos que saber cuantos bytes faltan hasta el último para generar correctamente un bloque
	disasm, err := r2p.Cmd("b " + strconv.Itoa(int(block)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}

	disasm2, err := r2p.Cmd("s " + strconv.Itoa(int(header)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm2, "")
	}

	disasm3, err := r2p.Cmd("ph md5")
	if err != nil {
		print("ERROR: ", err)
	} else {
		fmt.Println(disasm3)
	}
	//return disasm3

}


func dumpRadare(rawdisk string, header string, rule string, index string) {
	// var offset int
	// var i uint64
	r2p4, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
		fmt.Println("can't open")
	}
	//defer r2p4.Close()
	//fmt.Println("after open")
	r2p4.Cmd("s " + header)

	r2p4.Cmd("wtf ./tmp " + maxSizeDump)


	r2p5, err := r2pipe.NewPipe("./tmp")
	if err != nil {
		print("ERROR: ", err)
		fmt.Println("can't open")
	}

	r2p5.Cmd("s 0x0")

	disasm6, err := r2p5.Cmd("iZ")
	if err != nil {
		print("ERROR: ", err)
	} else {
		//disasm6:=""
		//print(disasm6, "")
	}

	//The block is hardcoded 'cause it fails with bigger blocks
	r2p5.Cmd("b " + maxSizeDump)
	

	Footer = disasm6
	//fmt.Println("calc size")
	r2p5.Cmd("wtf " + rule + "_" + index)
	

	//err2 := os.Remove(workspace+"/tmp")

	// if err2 != nil {
	//   fmt.Println(err2)
	//   return
	// }

	r2p4.Close()
}



func dumpRadareFooter(rawdisk string, header uint64, lastAddress uint64, rule string, index string) {

	//fmt.Println(rule)
	//fmt.Println(index)

	block := lastAddress - header
	//fmt.Println(block)

	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()

	// tener en cuenta que el match se hace al princpio de la cadena y
	//tenemos que saber cuantos bytes faltan hasta el último para generar correctamente un bloque
	disasm, err := r2p.Cmd("b " + strconv.Itoa(int(block)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}

	disasm2, err := r2p.Cmd("s " + strconv.Itoa(int(header)))

	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm2, "")
	}

	// disasm3, err := r2p.Cmd("px")

	// if err != nil {
	// 	print("ERROR: ", err)
	// } else {
	// 	print(disasm3, "")
	// }

	disasm3, err := r2p.Cmd("wtf " + rule + "_" + index)
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm3, "")
	}

	r2p.Close()

}


func radareCmd2(argument []string, rawdisk string, header string) {


	command := ""
	for _, b := range argument {

		command += b + " "
	}
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}
	defer r2p.Close()
	// disasm, err := r2p.Cmd("s 0x0")
	// if err != nil {
	// 	print("ERROR: ", err)
	// } else {
	// 	disasm:=""
	// 	print(disasm, "")
	// }
	r2p.Cmd("s "+header)

	disasm2, err := r2p.Cmd(command)
	if err != nil {
		print("ERROR: ", err)
	} else {
		//disasm2:=""
		print(disasm2, "")
	}

}


func radareCmd(argument []string, rawdisk string) {


	for _, elem := range sliceSet {
		rawdisk = elem.Rule + "_" + strconv.Itoa(elem.Index)
	}
	if argument[0] == "!" {
	} else {

		command := ""
		for _, b := range argument {

			command += b + " "
		}
		r2p, err := r2pipe.NewPipe(rawdisk)
		if err != nil {
			print("ERROR: ", err)
		}
		defer r2p.Close()
		// disasm, err := r2p.Cmd("s 0x0")
		// if err != nil {
		// 	print("ERROR: ", err)
		// } else {
		// 	disasm:=""
		// 	print(disasm, "")
		// }
		fmt.Println(argument)
		fmt.Println(command)
		disasm2, err := r2p.Cmd(command)
		if err != nil {
			print("ERROR: ", err)
		} else {
			//disasm2:=""
			print(disasm2, "")
		}
	}

}


func radareSession(rawdisk string) bool {
	fmt.Println()
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	fmt.Println(text)
	for true {
		disasm, err := r2p.Cmd(text)
		if err != nil {
			print("ERROR: ", err)
		} else {
			print(disasm, "")
		}
		reader = bufio.NewReader(os.Stdin)
		text, _ = reader.ReadString('\n')
		if text == "ex" {
			r2p.Close()
			return true
		}

	}
	return false
}



func uploadRadare(rawdisk string, header string, size string, host string, port string) {

	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()

	disasm, err := r2p.Cmd("s " + header)
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm, err = r2p.Cmd("wts " + host + ":" + port + " " + size)
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
}


func dumpMaxSize(elem result) {
	rawdisk = totrawdisk
	fmt.Println(elem)
	maxsizeInt, err := strconv.ParseFloat(maxsize, 64)
	if err != nil {
	}
	r2p, err := r2pipe.NewPipe(rawdisk)
	if err != nil {
		print("ERROR: ", err)
	}

	defer r2p.Close()
	disasm, err := r2p.Cmd("s " + strconv.Itoa(int(elem.offset)))
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	defer r2p.Close()
	disasm, err = r2p.Cmd("s -" + maxSizeDump)
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm, err = r2p.Cmd("px")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "")
	}
	disasm3, err := r2p.Cmd("wtf ./tmp " + strconv.FormatFloat(maxsizeInt*2, 'f', 6, 64))
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm3, "")
	}
}


