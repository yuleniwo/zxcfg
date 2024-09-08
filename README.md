# zxcfg
ZTE CFG file and XML file unpacking and packaging tool.

<pre><code>
Usage: zxcfg [OPTIONS]
Options:
  -i  input file name
  -o  output file name
  -m  mode
      0 --- unpack cfg or xml file (default mode)
      1 --- pack into xml file
      2 --- pack into cfg file
      3 --- unpack hardcode file(/etc/hardcodefile/)
  -t  pack type (pack mode only)
      0 --- compress
      1 --- compress, encrypt with default key
      2 --- compress, encrypt with user key
  -k  aescbc encrypt & decrypt key
  -v  aescbc encrypt & decrypt iv
  -g  generate aescbc key method
      0 --- sha256(default, if the "-k" option is not specified)
      1 --- md5, sha256(default, if the "-k" option is specified)
  -n  device model name.(only used to pack into cfg. default: ZXHN F7015TV3)
  -l  byte order.(only used to pack into cfg. default: 0)
      0 --- big endian
      1 --- little endian
  -c  cfg type (only used to pack into cfg. default: 2)
  -d  defcfg type (only used to pack into cfg. default: 0)
</code></pre>
