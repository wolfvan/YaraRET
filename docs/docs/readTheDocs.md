
	start all: YaraRET looks for all headers in YaraRET

	start {file type}: Only initialize the specified file type

- Supported headers
```

	threegp    		sevenzip			amazonkindleupdate
	appleworks5	 	appleworks6			avi	
	bmp				bzip				canonraw
	crx				dalvik				dat
	dba				deb					dmg
	doc				elf64				flac	
	flash			gif					gzip	
	is				javaclass			jpg
	kodakcineon		macho				microsoftOffice
	midi			mkv					mp3
	mpeg			ost					pcap
	pcapng			pdf					pe
	png				pds					pst
	pyc				rar					rpm
	rtf				tape				tar	
	tarzip			tiff				utf8
	vmdk			wasm				wav
	woff			xar					xml
	xz				zip					zlib


```



``` 
yara {yaraFile}: Run yara over the selected structures.
```
```
ioc {iocFile}: Run any kind of IoC over selected structures.
```
```
hash: Get the hash of selected structures.
```
```
dump: Exports selected structures.
```
```
save: Saves all obtained information in a json.
```
```
open: Opens saved information
```
```
show: Puts in the screen all selected structures
```
```
tag: Command for adding information in the structure.
```
```
yaraforensics: YaraRET runs the ruleset of Yara Forensics repository.
```
```
~ {radareCommand}: Runs radare command over selected structure.
```
```
vti key: Command for putting the VirusTotal API Key
```
```
vti scan: Uploads selected structure to VirusTotal
```
```
vti report: Checks the hash to VirusTotal
```
```
ssdeep: Calculates the ssdeep value for selected structure.
```
```
ssdeep path {pathOfFiles} : Checks ssdeep of selected structures with all ssdeeps 
```
```
run {script}: YaraRET allows running commands written in a simple text file. It helps when you know that analysis is going to take too much time.
```
```
entropy: Calculate the entropy of selected structures.
```
```
upload: YaraRET sends the selected structure to specified server.
```
```
set {file type}: In case that all data had been initialized, this command selects only one type of files for running nexts commands.
```
```
set footer: In case that our file type has a footer in its structure YaraRET will find the end of the file and the size. If doesn’t have a footer YaraRET will take the specified maximum size.
Special case with PE format, which is calculated with binary header.
```
- Supported footers

```
pdf jpg 
gif doc 
mft
```

```
set footer generic: If we don’t want to spend so much time calculating the real footer of the file, we can run this command for selecting the specified maximum size. It’s a good option if we don’t have any idea of what we are looking for.
```


```
set yara {rule}: Selects the structures which have matched with specified rule
```
```
set ioc {ioc}: Selects the structures which have matched with specified ioc
```
```
set entropy < | >: Selects the structures which were greater or lesser than specified value
```
```
var {globalVariable} : Change the value of global variables.
```
```
var maxsize {value}: Changes the value of the maxsize used in footer finding.
```
```
var history: After this command, every command is going to be saved in a file. Very useful if this 
```



