# muts-opt-encoder

Pure python, self-contained, independent implementation of the `add_sub` encoder and its optimized version (aka `opt_sub`).

## Notes:

The script implements the same encoding scheme of add_sub and opt_sub msfvenom encoders, while mantaining a crucial difference:

* By design, the script will generate only NASM instructions, not shellcode. I created it as a mean to understand the encoding scheme. If you want a ready to use shellcode, `add_sub` and `opt_sub` from msfvenom are your friends.

The name, "Muts Optimised Encoder", is to remember the original author of this beautiful encoding scheme, Muts, who created it while developing the famous HP OpenView NNM 7.5.1 exploit, available [here](http://www.exploit-db.com/exploits/5342/).
This encoding scheme is a piece of art in my opinion, as well as its 2 main implementations.

## Usage

muts-opt-encoder has a few useful options, below:

```
usage: muts-opt-encoder [-h] (-f FILE | -s STDIN) [-a] [-m {add-sub,opt-sub}]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Get input from a file (default: None)
  -s STDIN, --stdin STDIN
                        Get input from stdin (default: None)
  -a, --append          Append NASM instructions in "encoder.nasm" (default:
                        False)
  -m {add-sub,opt-sub}, --mode {add-sub,opt-sub}
                        Operational mode (default: opt-sub)
```

A few things to notice:

* It accepts payloads as hex strings, hex files or binary files
* The append version allows to append the nasm code to an existent nasm snippet

## Todo

There are a few things I would like to add in the future:

* Cleaning the code
* Add Python3 support

There are a few things that I won't introduce, as I don't want to:

* Automatic shellcode generation

## Contributing

In the unlikely event you would like to contribute, please fork the repository at [https://github.com/klezVirus/muts-opt-encoder](https://github.com/klezVirus/muts-opt-encoder) and use that. Any help to improve it is very welcome.

If you want to get in touch with me github is your best choice.

## References

A few presentation about automating this encoding scheme had already been presented many times:

* https://armoredcode.com/blog/a-tale-of-a-restricted-charset-shellcode-generation/
* http://xangosec.blogspot.com/2014/08/automating-sub-encoder.html
* http://www.negation.net/papers/encoding_shellcode/

## Credits:

* Sagi Shahar

This script is an advanced version of the tool created by Sagi Shahar, available here: [muts-encoder](https://github.com/sagishahar/scripts/blob/master/muts_encoder.py).
