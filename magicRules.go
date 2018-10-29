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
	yara "github.com/hillu/go-yara"
	"fmt"
	"strings"
	"os"
	"sort"
	"log"

)


type fileDump struct{
	offsetHeader uint64
	offsetFooter uint64
	filetype string
	rule string
	data []byte
}


type result struct {
	rule   string
	offset uint64
	Data   []byte
}

type offsetSorter []result

func (a offsetSorter) Len() int           { return len(a) }
func (a offsetSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a offsetSorter) Less(i, j int) bool { return a[i].offset < a[j].offset }



func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}


func yaraStage2(rawdisk string, yarafile string) []result{

	var v []result

	comp, err := yara.NewCompiler()
	rules, err := comp.GetRules()
	if err != nil {
		fmt.Println(err)
	}	
	matches, err := rules.ScanFile(rawdisk, 0, 0)
	if err != nil {
		fmt.Println(err)
	}	

	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
		}
	}
	sort.Sort(offsetSorter(v))
	return v
}






func yaraStage1(rawdisk string, yarafile string) []result{

	var v []result
	comp, err := yara.NewCompiler()
	f, err := os.Open(yarafile)
	if err != nil {
		log.Fatalf("Could not open rule file: %s", err)
	}
	comp.AddFile(f, "")
	rules, err := comp.GetRules()
	if err != nil {
		fmt.Println(err)
	}

	matches, err := rules.ScanFile(rawdisk, 0, 0)
	if err != nil {
		fmt.Println(err)
	}

	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
		}
	}
	sort.Sort(offsetSorter(v))
	return v

}


func findFooter(filetype string, rawdisk string) []result{
	var v []result
	comp, err := yara.NewCompiler()
	if err != nil {
		fmt.Println(err)
	}		
	rule := buildRuleAny(filetype)
	comp.AddString(rule, "")
	//fmt.Println(rule)
	rules, err := comp.GetRules()
	if err != nil {
		fmt.Println(err)
	}
	matches, err := rules.ScanFile(rawdisk, 0, 0)

	for _, matches := range matches {
		for _, stringf := range matches.Strings {
			s := result{rule: matches.Rule, offset: stringf.Offset, Data: stringf.Data}
			v = append(v, s)
		}
	}
	sort.Sort(offsetSorter(v))
	return v
}



func buildRuleAny(filetype string) string{
	body := returnBodyFooter(filetype)
	//body1 := strings.Replace(body,"COUNT",strconv.Itoa(count),-1)
	//fmt.Println(body1)
	condition := returnConditionAny()
	//fmt.Println(condition)
	rule := body+condition
	
	return rule

}





func buildRule(offset1 string, offset2 string, filetype string) string{
	body := returnBody(filetype)
	//body1 := strings.Replace(body,"COUNT",strconv.Itoa(count),-1)
	//fmt.Println(body1)
	condition := returnCondition(offset1, offset2)
	//fmt.Println(condition)
	rule := body+condition
	
	return rule

}


func returnCondition(offset1 string, offset2 string)string{

	condition :=`condition:		        
	$a in (OFFSET1..OFFSET2) 		        	    
}
`
	condition1 := strings.Replace(condition, "OFFSET1", offset1, -1)
	condition2 := strings.Replace(condition1, "OFFSET2", offset2, -1)
	return condition2
}


func returnConditionAny() string{

	condition :=`condition:		        
	$a
}
`
	return condition
}



func returnBody(type1 string)string{

var body string

	switch option := type1; option {

	case "threegp":

		body=`rule threegp_header_COUNT: THREEGP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {66 74 79 70 33 67}

		    
`


	case "sevenzip":

		body=`rule sevenzip_header_COUNT: SEVENZIP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {37 7A BC AF 27 1C}

		    
`


	case "amazonkindleupdate":

		body=`rule amazonkindleupdate_header_COUNT: AMAZONBIN
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {53 50 30 31}


		    
`



	case "appleworks5":

		body=`rule appleworks5_header_COUNT: APPLEWORKS5
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {05 07 00 00 42 4F 42 4F}
		        

		    
`



	case "appleworks6":

		body=`rule appleworks6_header_COUNT: APPLEWORKS6
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {06 07 E1 00 42 4F 42 4F}
		        

		    
`



	case "avi":

		body=`rule avi_header_COUNT: AVI
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {52 49 46 46 ?? ?? ?? ?? 41 56 49 20}

		    
`



	case "bmp":

		body=`rule bmp_header_COUNT: BMP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {42 4D ?? ?? ?? 00 }


		    
`



	case "bzip":

		body=`rule bzip_header_COUNT: BZIP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {42 5A 68}


		    
`



	case "canonraw":

		body=`rule canonraw_header_COUNT: CANONRAW
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {49 49 2A 00 10 00 00 00}

		    
`



	case "crx":

		body=`rule crx_header_COUNT: CRX
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {05 07 00 00 42 4F 42 4F}


		    
`



	case "dalvik":

		body=`rule dalvik_header_COUNT: DALVIK
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {64 65 78 0A 30 33 35 00}

		    
`



	case "dat":

		body=`rule dat_header_COUNT: DAT
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {50 4D 4F 43 43 4D 4F 43}


		    
`


	case "dba":

		body=`rule dba_header_COUNT: PALMDESKTOP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {BE BA FE CA}



		    
	`



	case "deb":

		body=`rule deb_header_COUNT: DEB
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {21 3C 61 72 63 68 3E}


		    
`



	case "dmg":

		body=`rule dmg_header_COUNT: DMG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {78 01 73 0D 62 62 60}


		    
`


	case "doc":

		body=`rule doc_header_COUNT: DOC
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {d0 cf 11 e0 a1 b1 1a e1 00 00}


		    
`



	case "elf64":

		body=`rule elf64_header_COUNT: ELF64
{
	meta:
	author = "Joan Bono"

strings:
	$a = { 7F 45 4C 46 }

		    
`




	case "flac":

		body=`rule flac_header_COUNT: FLAC
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {66 4C 61 43}

		    
`



	case "flash":

		body=`rule flash_header_COUNT: FLASH
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {46 57 53}

		    
`



	case "gif":

		body=`rule gif_header_COUNT: GIF
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {ff d8 ff e0 00 10}    

		    
`



	case "gzip":

		body=`rule gzip_header_COUNT: GZIP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {1F 8B}

		    
`





	case "is":

		body=`rule isoheader: ISO
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {43 44 30 30 31}

		    
`



	case "javaclass":

		body=`rule javaclass_header_COUNT: JAVA
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {CA FE BA BE}


		    
`



	case "jpg":

		body=`rule jpg_header_COUNT: JPG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {ff d8 ff e0 00 10}
		        


		    
	`



	case "kodakcineon":

		body=`rule kodakcineon_header_COUNT: KODAKCINEON
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {80 2A 5F D7}

		    
`



	case "macho":

		body=`rule macho_header_COUNT: MACHO
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {FE ED FA CE}
		        

		    
`
	case "mft":

		body=`rule mft_header_COUNT: MFT
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {46 49 4C 45 30}
		        

		    
`
	case "microsoftOffice":

		body=`rule microsoftOffice_header_COUNT: MICROSOFTOFFICE
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {D0 CF 11 E0 A1 B1 1A E1}

		    
`



	case "midi":

		body=`rule midi_header_COUNT: MIDI
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {4D 54 68 64}

		    
`


	case "mkv":

		body=`rule mkv_header_COUNT: MKV
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {1A 45 DF A3}

		    
`


	case "mp3":

		body=`rule mp3_header_COUNT: MP3
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {FF FB}

		    
`



	case "mpeg":

		body=`rule mpeg_header_COUNT: MPEG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {00 00 01 BA}


		    
`



	case "ost":

		body=`rule ost_header_COUNT: BMP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = { 21 42 44 4e}


		    
`



	case "pcap":

		body=`rule pcap_header_COUNT: PCAP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {a1 b2 c3 d4}



		    
	`



	case "pcapng":

		body=`rule pcapng_header_COUNT: PCAPNG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {0a 0d 0d 0a}


		    
`



	case "pdf":

		body=`rule pdf_header_COUNT: PDF
{
	meta:
	author = "Joan Soriano"

strings:
	$a = "%PDF"

		    
`



	case "pe":

		body=`rule pe_header_COUNT: EXE
{
	meta:
	author = "Joan Soriano"

strings:
	$a = { 4d 5a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 21 ?? ??}

		    
`


	case "png":

		body=`rule png_header_COUNT: PNG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {89 50 4E 47 0D 0A 1A 0A}


		    
`



	case "pds":

		body=`rule pds_header_COUNT: PSD
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {38 42 50 53}

		    
`



	case "pst":

		body=`rule pst_header_COUNT: BMP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = { 21 42 4e a5 6f b5 a6}


		    
`



	case "pyc":

		body=`rule pyc_header_COUNT: PYC
{
	meta:
	author = "Joan Soriano"

strings:
	$a = { 03 f3 0d 0a }

		    
`




	case "rar":

		body=`rule rar_header_COUNT: RAR
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {52 61 72 21 1A 07 00}


		    
`



	case "rpm":

		body=`rule rpm_header_COUNT: RPM
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {ed ab ee db}


		    
`



	case "rtf":

		body=`rule rtf_header_COUNT: RTF
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {7B 5C 72 74 66 31}


		    
`



	case "tape":

		body=`rule tape_header_COUNT: TAPE
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {54 41 50 45}


		    
`



	case "tar":

		body=`rule tar_header_COUNT: TAR
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {75 73 74 61 72 00 30 30}

		    
`


	case "tarzip":

		body=`rule tarzip_header_COUNT: TARZIP
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {1F 9D}



		    
	`



	case "tiff":

		body=`rule tiff_header_COUNT: TIFF
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {49 49 2A 00}

		    
`



	case "utf8":

		body=`rule utf8_header_COUNT: UTF8
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {EF BB BF}


		    
`



	case "vmdk":

		body=`rule vmdk_header_COUNT: VMDK
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {4B 44 4D}

		    
`



	case "wasm":

		body=`rule wasm_header_COUNT: WASM
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {00 61 73 6d}

		    
`


	case "wav":

		body=`rule wav_header_COUNT: WAV
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {52 49 46 46 ?? ?? ?? ?? 57 41 56 45}

		    
`



	case "woff":

		body=`rule woff_header_COUNT: WOFF
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {77 4F 46 46}

		    
`


	case "xar":

		body=`rule xar_header_COUNT: XAR
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {78 61 72 21}


		    
`


	case "xml":

		body=`rule xml_header_COUNT: XML
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {3c 3f 78 6d 6c 20}

		    
`


	case "xz":

		body=`rule xz_header_COUNT: XZ
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {FD 37 7A 58 5A 00 00}

		    
`


	case "zip":

		body=`rule zip_header_COUNT: ZIP
{
	meta:
	author = "Joan Soriano"

strings:
	$a = { 50 4b 03 04}

		    
`


	case "zlib":

		body=`rule zlib_header_COUNT: ZLIB
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {78 01}
		        
		    
`
	}
	return body
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



func returnBodyFooter(type1 string)string{

var body string

	switch option := type1; option {

	case "pdf":

		body=`rule pdf_footer_COUNT: PDF
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {25 45 4f 46 0d}

		    
`


	case "jpg":

		body=`rule jpg_footer_COUNT: JPG
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {ff d9}

		    
`


	case "gif":

		body=`rule gif_footer_COUNT: AMAZONBIN
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {00 3b}


		    
`

	case "mft":

		body=`rule mft_footer_COUNT: MFT
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {79 47 11}


		    
`


	case "doc":

		body=`rule doc_footer_COUNT: APPLEWORKS5
{
	meta:
	author = "Joan Soriano"

strings:
		        
	$a = {d0 cf 11 e0 a1 b1 1a e1 00 00}
		        

		    
`

	}
	return body
}
