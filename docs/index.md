
# YaraRET

# Introduction

YaraRET is a carving tool based in Radare2 and Yara and written in Go. It provides 58 magic number's yara rules for detecting 58 types of files.

This tool is based on the idea of a first stage detecting files using its magic numbers and a second stage, selecting or discarding those detected files using Yara, IoC or its entropy value.
 After that, it is able to generate the hash, the ssdeep (and check it over anothers).
 Also provides an integration with VirusTotal.
 
 
In order to deal with forensics cases based on weak clues, YaraRET provides different modes for raw disk handling.



# Install

For a compiled bin, you can download last release from Github.

Also, you can  download git repo and build it.

#### Dependencies

Yara
Radare2

	github.com/abiosoft/ishell
	github.com/docopt/docopt-go
	github.com/glaslos/ssdeep
	github.com/hillu/go-yara
	github.com/radare/r2pipe-go
	github.com/williballenthin/govt

	
	


# Usage

YaraRET provides diferent modes for handling different forensics cases. 

 If you are interested in get a file from a yara rule, you can execute the following command:
 


	$  ./yaraRET yara myYaraRule rawdisk myRaw maxsize 3000 
	
	

If you are interested in get a file from an IoC like a domain or hash from any kind of file like STIX or txt

	$ ./yaraRET ioc ./myIOC.stix rawdisk myRaw maxsize 3000
	
 


For a complex analysis, YaraRET provides a shell mode which allows an analysis at the tool's opening 

	$  ./yaraRET rawdisk myRaw shell 


	>> start all
	>> set pe
	>> show -
	
	
# Features

- Radare2 integration
- SSdeep distance checking
- VirusTotal API integration
- Scripting
- YaraForensics Ruleset
- Entropy
- Boot Sector analysis

 
 This tool was introduced in this talk at r2con 2018
 
 - https://www.youtube.com/watch?v=trLVw9J-mfw
 
 - https://github.com/radareorg/r2con2018/blob/master/talks/08-YaraRET/NotAnotherRET.pdf
 
