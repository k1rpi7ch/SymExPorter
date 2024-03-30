# SymExPorter
This is an upgraded fork of [syms2elf](https://github.com/danigargu/syms2elf) with new features. The plugin exports symbols recognized by IDA, radare2, rizin & cutter to the ELF symbol table. This allows us to use IDA/r2/rizin/cutter capabilities in recognition functions (analysis, FLIRT signatures, manual creation, renaming, etc), but not be limited to the exclusive use of this tools.

Supports both 32 and 64-bit file format.

### What's new?
* Added support for exporting global variable names, static variable names and constant names (the original syms2elf plugin supported exporting only function names).
* Plugin with new features was ported to rizin and cutter.

## INSTALLATION
  * **IDA**: Copy `SymExPorter.py` to the IDA's plugins folder. The plugin will appear in Edit-->Plugins menu.
  * **radare2**: Copy `SymExPorter.py` to the radare2's bin folder. Then, in radare2 environment, pass this command: `#!pipe python ./SymExPorter.py <output_file>`.
  * **rizin**: Copy `SymExPorter.py` to the rizin's bin folder. Then, in rizin environment, pass this command: `#!pipe python ./SymExPorter.py <output_file>`.
  * **cutter**: Copy `SymExPorter.py` to the Cutter's plugins/python folder. The plugin will appear in Windows-->Plugins menu.
  
	### Requirements:
	* r2pipe
	* rzpipe
	* Pyside2

## EXAMPLE
Based on a full-stripped ELF:

```
$ file testelf 
testelf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, for GNU/Linux 3.2.0, stripped
```

Rename some functions and global variables in IDA, r2, rizin (cutter) run `SymExPorter` and select the output file.

![IDA_example](https://github.com/k1rpi7ch/SymExPorter/assets/68912253/54375e07-f556-4135-9a99-17e1eb10bb1f)

![radare2_example](https://github.com/k1rpi7ch/SymExPorter/assets/68912253/44ae1a12-c366-48c4-8bb8-a5ee8e092f30)

![rizin_example](https://github.com/k1rpi7ch/SymExPorter/assets/68912253/d458ecda-17e5-4fae-bc1c-2c9601aeb640)

![cutter_example](https://github.com/k1rpi7ch/SymExPorter/assets/68912253/f8af6b1a-9ca6-4f6a-8a68-14883012e2cd)

After that:

```
$ file testelf_repaired 
testelf_repaired: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, for GNU/Linux 3.2.0, not stripped
```

Now you can open this file with other tools and continue analyzing it.

## AUTHORS
  * Daniel García (@danigargu)
  * Jesús Olmos (@sha0coder)
  * Kirill Magaskin (@K1RPI7CH)

## CONTACT 
Any comment, issue or pull request will be highly appreciated!

This modification was started as a part of [Digital Security](https://github.com/DSecurity)'s Research Centre internship "Summ3r of h4ck 2022".
