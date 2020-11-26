import re 

fp_list = {
  "UTF8": [
      {
      "name": "PHP Serialized",
      "extension": "bash",
      "mime": "application/bash",
      "description": "",
      "regex":  b".*a:[0-9]+:{.*"
    },
    {
      "name": "Bash Script",
      "extension": "bash",
      "mime": "application/bash",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x2f",
        3: b"\x62",
        4: b"\x69",
        5: b"\x6e",
        6: b"\x2f",
        7: b"\x62",
        8: b"\x61",
        9: b"\x73",
        10: b"\x68"
      }, 
      "regex":  b".*\x23\x21\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68.*"
    },
    {
      "name": "Shell Script",
      "extension": "sh",
      "mime": "application/sh",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x2f",
        3: b"\x62",
        4: b"\x69",
        5: b"\x6e",
        6: b"\x2f",
        7: b"\x73",
        8: b"\x68"
      },
      "regex": b"\x23\x21\x2f\x62\x69\x6e\x2f\x73\x68"
    },
    {
      "name": "Python",
      "extension": "py,pyc,pyd,pyo,pyw,pyz",
      "mime": "application/python",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x2f",
        3: b"\x75",
        4: b"\x73",
        5: b"\x72",
        6: b"\x2f",
        7: b"\x62",
        8: b"\x69",
        9: b"\x6e",
        10: b"\x2f",
        11: b"\x70",
        12: b"\x79",
        13: b"\x74",
        14: b"\x68",
        15: b"\x6f",
        16: b"\x6e",
        17: [
          b"\x32",
          b"\x33",
          b"\x0a",
          b"\x0d"
        ]
      },
      "regex": b"\x23\x21\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e"
    },
    {
      "name": "Ruby",
      "extension": "rb",
      "mime": "application/ruby",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x2f",
        3: b"\x75",
        4: b"\x73",
        5: b"\x72",
        6: b"\x2f",
        7: b"\x62",
        8: b"\x69",
        9: b"\x6e",
        10: b"\x2f",
        11: b"\x72",
        12: b"\x75",
        13: b"\x62",
        14: b"\x79"
      },
      "regex": b"\x23\x21\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x72\x75\x62\x79"
    },
    {
      "name": "perl",
      "extension": "pl,pm,t,pod",
      "mime": "application/perl",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x2f",
        3: b"\x75",
        4: b"\x73",
        5: b"\x72",
        6: b"\x2f",
        7: b"\x62",
        8: b"\x69",
        9: b"\x6e",
        10: b"\x2f",
        11: b"\x70",
        12: b"\x65",
        13: b"\x72",
        14: b"\x6c"
      },
      "regex": b"\x23\x21\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72\x6c"
    },
    {
      "name": "php",
      "extension": "php,phtml,php3,php4,php5,php7,phps,php-s,pht,phar",
      "mime": "application/php",
      "description": "",
      "magic_bytes": {
        0: b"\x3c",
        1: b"\x3f",
        2: b"\x70",
        3: b"\x68",
        4: b"\x70"
      },
      "regex": b"(\x3c\x3f\x70\x68\x70|\x3c\x3f\x3d)"
    }
  ],
  "BIN": [
    {
      "name": "Java Serialized",
      "extension": "",
      "mime": "",
      "description": "",
      "regex" : b".*\xac\xed\x00\x05.*"
    },
    {
      "name": "Windows Portable Executable",
      "extension": "exe,dll,drv,vxd,sys,ocx,vbx,com,fon,scr",
      "mime": "application/vnd.microsoft.portable-executable",
      "description": "",
      "magic_bytes": {
        0: b"\x4d",
        1: b"\x5a",
        3: [
          b"\x00",
          b"\x01",
          b"\x02"
        ],
        5: [
          b"\x00",
          b"\x01",
          b"\x02"
        ]
      }
    },
    {
      "name": "ELF Executable",
      "extension": "elf,bin,axf,o,prx,so",
      "mime": "application/x-executable",
      "description": "Executable and Linkable Format file. No standard file extension.",
      "magic_bytes": {
        0: b"\x7f",
        1: b"\x45",
        2: b"\x4c",
        3: b"\x46"
      }
    },
    {
      "name": "MacOS Mach-O object",
      "extension": "dylib",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": [
        {
          0: b"\xca",
          1: b"\xfe",
          2: b"\xba",
          3: b"\xbe",
          4: b"\x00",
          5: b"\x00",
          6: b"\x00",
          7: [
            b"\x01",
            b"\x02",
            b"\x03"
          ]
        },
        {
          0: b"\xce",
          1: b"\xfa",
          2: b"\xed",
          3: b"\xfe",
          4: b"\x07",
          5: b"\x00",
          6: b"\x00",
          7: b"\x00",
          8: [
            b"\x01",
            b"\x02",
            b"\x03"
          ]
        }
      ]
    },
    {
      "name": "MacOS Mach-O 64-bit object",
      "extension": "dylib",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\xcf",
        1: b"\xfa",
        2: b"\xed",
        3: b"\xfe"
      }
    },
    {
      "name": "Adobe Flash",
      "extension": "swf",
      "mime": "application/x-shockwave-flash",
      "description": "",
      "magic_bytes": {
        0: [
          b"\x43",
          b"\x46"
        ],
        1: b"\x57",
        2: b"\x53"
      }
    },
    {
      "name": "Java Class",
      "extension": "class",
      "mime": "application/java-vm",
      "description": "",
      "magic_bytes": {
        0: b"\xca",
        1: b"\xfe",
        2: b"\xba",
        3: b"\xbe"
      }
    },
    {
      "name": "Dalvik Executable",
      "extension": "dex",
      "mime": "application/octet-stream",
      "description": "Dalvik Executable as used by Android",
      "magic_bytes": {
        0: b"\x64",
        1: b"\x65",
        2: b"\x78",
        3: b"\x0a",
        4: b"\x30",
        5: b"\x33",
        6: b"\x35",
        7: b"\x00"
      }
    },
    {
      "name": "Google Chrome Extension",
      "extension": "crx",
      "mime": "application/crx",
      "description": "Google Chrome extension or packaged app",
      "magic_bytes": {
        0: b"\x43",
        1: b"\x72",
        2: b"\x32",
        3: b"\x34"
      }
    },
    {
      "name": "PKZIP archive",
      "extension": "zip",
      "mime": "application/zip",
      "description": "",
      "magic_bytes": {
        0: b"\x50",
        1: b"\x4b",
        2: [
          b"\x03",
          b"\x05",
          b"\x07"
        ],
        3: [
          b"\x04",
          b"\x06",
          b"\x08"
        ]
      }
    },
    {
      "name": "TAR archive",
      "extension": "tar",
      "mime": "application/x-tar",
      "description": "",
      "magic_bytes": {
        257: b"\x75",
        258: b"\x73",
        259: b"\x74",
        260: b"\x61",
        261: b"\x72"
      }
    },
    {
      "name": "RAR Archive",
      "extension": "rar",
      "mime": "application/x-rar-compressed",
      "description": "",
      "magic_bytes": {
        0: b"\x52",
        1: b"\x61",
        2: b"\x72",
        3: b"\x21",
        4: b"\x1a",
        5: b"\x07",
        6: [
          b"\x00",
          b"\x01"
        ]
      }
    },
    {
      "name": "7zip",
      "extension": "7z",
      "mime": "application/x-7z-compressed",
      "description": "",
      "magic_bytes": {
        0: b"\x37",
        1: b"\x7a",
        2: b"\xbc",
        3: b"\xaf",
        4: b"\x27",
        5: b"\x1c"
      }
    },
    {
      "name": "xz compression",
      "extension": "xz",
      "mime": "application/x-xz",
      "description": "",
      "magic_bytes": {
        0: b"\xfd",
        1: b"\x37",
        2: b"\x7a",
        3: b"\x58",
        4: b"\x5a",
        5: b"\x00"
      }
    },
    {
      "name": "Tarball",
      "extension": "tar.z",
      "mime": "application/x-gtar",
      "description": "",
      "magic_bytes": {
        0: b"\x1f",
        1: [
          b"\x9d",
          b"\xa0"
        ]
      }
    },
    {
      "name": "Virtual Machine Disk",
      "extension": "vmdk",
      "mime": "application/vmdk,application/x-virtualbox-vmdk",
      "description": "",
      "magic_bytes": {
        0: b"\x4b",
        1: b"\x44",
        2: b"\x4d",
        3: b"\x56",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Virtual Hard Drive",
      "extension": "vhd",
      "mime": "application/x-vhd",
      "description": "",
      "magic_bytes": {
        0: b"\x63",
        1: b"\x6f",
        2: b"\x6e",
        3: b"\x65",
        4: b"\x63",
        5: b"\x74",
        6: b"\x69",
        7: b"\x78"
      }
    },
    {
      "name": "Macintosh disk image",
      "extension": "dmf,dmg",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x78",
        1: b"\x01",
        2: b"\x73",
        3: b"\x0d",
        4: b"\x62",
        5: b"\x62",
        6: b"\x60",
        7: b"\x60"
      }
    },
    {
      "name": "ARJ Archive",
      "extension": "arj",
      "mime": "application/x-arj-compressed",
      "description": "",
      "magic_bytes": {
        0: b"\x60",
        1: b"\xea",
        8: [
          b"\x00",
          b"\x10",
          b"\x14"
        ],
        9: b"\x00",
        10: b"\x02"
      }
    },
    {
      "name": "WinAce Archive",
      "extension": "ace",
      "mime": "application/x-ace-compressed",
      "description": "",
      "magic_bytes": {
        7: b"\x2a",
        8: b"\x2a",
        9: b"\x41",
        10: b"\x43",
        11: b"\x45",
        12: b"\x2a",
        13: b"\x2a"
      }
    },
    {
      "name": "Macintosh BinHex Encoded File",
      "extension": "hqx",
      "mime": "application/mac-binhex",
      "description": "",
      "magic_bytes": {
        11: b"\x6d",
        12: b"\x75",
        13: b"\x73",
        14: b"\x74",
        15: b"\x20",
        16: b"\x62",
        17: b"\x65",
        18: b"\x20",
        19: b"\x63",
        20: b"\x6f",
        21: b"\x6e",
        22: b"\x76",
        23: b"\x65",
        24: b"\x72",
        25: b"\x74",
        26: b"\x65",
        27: b"\x64",
        28: b"\x20",
        29: b"\x77",
        30: b"\x69",
        31: b"\x74",
        32: b"\x68",
        33: b"\x20",
        34: b"\x42",
        35: b"\x69",
        36: b"\x6e",
        37: b"\x48",
        38: b"\x65",
        39: b"\x78"
      }
    },
    {
      "name": "ALZip Archive",
      "extension": "alz",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x41",
        1: b"\x4c",
        2: b"\x5a",
        3: b"\x01",
        4: b"\x0a",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "KGB Compressed Archive",
      "extension": "kgb",
      "mime": "application/x-kgb-compressed",
      "description": "",
      "magic_bytes": {
        0: b"\x4b",
        1: b"\x47",
        2: b"\x42",
        3: b"\x5f",
        4: b"\x61",
        5: b"\x72",
        6: b"\x63",
        7: b"\x68",
        8: b"\x20",
        9: b"\x2d"
      }
    },
    {
      "name": "Microsoft Cabinet",
      "extension": "cab",
      "mime": "vnd.ms-cab-compressed",
      "description": "",
      "magic_bytes": {
        0: b"\x4d",
        1: b"\x53",
        2: b"\x43",
        3: b"\x46",
        4: b"\x00",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Jar Archive",
      "extension": "jar",
      "mime": "application/java-archive",
      "description": "",
      "magic_bytes": {
        0: b"\x5f",
        1: b"\x27",
        2: b"\xa8",
        3: b"\x89"
      }
    },
    {
      "name": "JAR",
      "extension": "jar",
      "mime": "application/java-archive",
      "description": "",
      "magic_bytes": {
        0: b"\x50",
        1: b"\x4B",
        2: b"\x03",
        3: b"\x04",
        4: b"\x14",
        5: b"\x00",
        6: b"\x08",
        7: b"\x00",
        8: b"\x08",
        9: b"\x00"
      }
    },
    {
      "name": "lzop compressed",
      "extension": "lzop,lzo",
      "mime": "application/x-lzop",
      "description": "",
      "magic_bytes": {
        0: b"\x89",
        1: b"\x4c",
        2: b"\x5a",
        3: b"\x4f",
        4: b"\x00",
        5: b"\x0d",
        6: b"\x0a",
        7: b"\x1a"
      }
    },
    {
      "name": "Linux deb package",
      "extension": "deb",
      "mime": "application/vnd.debian.binary-package",
      "description": "",
      "magic_bytes": {
        0: b"\x21",
        1: b"\x3C",
        2: b"\x61",
        3: b"\x72",
        4: b"\x63",
        5: b"\x68",
        6: b"\x3e"
      }
    },
    {
      "name": "Apple Disk Image",
      "extension": "dmg",
      "mime": "application/x-apple-diskimage",
      "description": "",
      "magic_bytes": {
        0: b"\x78",
        1: b"\x01",
        2: b"\x73",
        3: b"\x0d",
        4: b"\x62",
        5: b"\x62",
        6: b"\x60"
      }
    },
    {
      "name": "Waveform Audio",
      "extension": "wav",
      "mime": "audio/x-wav",
      "description": "",
      "magic_bytes": {
        0: b"\x52",
        1: b"\x49",
        2: b"\x46",
        3: b"\x46",
        8: b"\x57",
        9: b"\x41",
        10: b"\x56",
        11: b"\x45"
      }
    },
    {
      "name": "OGG audio",
      "extension": "ogg",
      "mime": "audio/ogg",
      "description": "",
      "magic_bytes": {
        0: b"\x4f",
        1: b"\x67",
        2: b"\x67",
        3: b"\x53"
      }
    },
    {
      "name": "Musical Instrument Digital Interface audio",
      "extension": "midi",
      "mime": "audio/midi",
      "description": "",
      "magic_bytes": {
        0: b"\x4d",
        1: b"\x54",
        2: b"\x68",
        3: b"\x64"
      }
    },
    {
      "name": "MPEG-3 audio",
      "extension": "mp3",
      "mime": "audio/mpeg",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x49",
          1: b"\x44",
          2: b"\x33"
        },
        {
          0: b"\xff",
          1: b"\xfb"
        }
      ]
    },
    {
      "name": "MPEG-4 Part 14 audio",
      "extension": "m4a",
      "mime": "audio/m4a",
      "description": "",
      "magic_bytes": [
        {
          4: b"\x66",
          5: b"\x74",
          6: b"\x79",
          7: b"\x70",
          8: b"\x4d",
          9: b"\x34",
          10: b"\x41"
        },
        {
          0: b"\x4d",
          1: b"\x34",
          2: b"\x41",
          3: b"\x20"
        }
      ]
    },
    {
      "name": "Free Lossless Audio Codec",
      "extension": "flac",
      "mime": "audio/x-flac",
      "description": "",
      "magic_bytes": {
        0: b"\x66",
        1: b"\x4c",
        2: b"\x61",
        3: b"\x43"
      }
    },
    {
      "name": "Adaptive Multi-Rate audio codec",
      "extension": "amr",
      "mime": "audio/amr",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x21",
        2: b"\x41",
        3: b"\x4d",
        4: b"\x52",
        5: b"\x0a"
      }
    },
    {
      "name": "Audacity",
      "extension": "au",
      "mime": "audio/x-au",
      "description": "",
      "magic_bytes": {
        0: b"\x64",
        1: b"\x6e",
        2: b"\x73",
        3: b"\x2e",
        24: b"\x41",
        25: b"\x75",
        26: b"\x64",
        27: b"\x61",
        28: b"\x63",
        29: b"\x69",
        30: b"\x74",
        31: b"\x79",
        32: b"\x42",
        33: b"\x6c",
        34: b"\x6f",
        35: b"\x63",
        36: b"\x6b",
        37: b"\x46",
        38: b"\x69",
        39: b"\x6c",
        40: b"\x65"
      }
    },
    {
      "name": "Audacity Block",
      "extension": "auf",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x41",
        1: b"\x75",
        2: b"\x64",
        3: b"\x61",
        4: b"\x63",
        5: b"\x69",
        6: b"\x74",
        7: b"\x79",
        8: b"\x42",
        9: b"\x6c",
        10: b"\x6f",
        11: b"\x63",
        12: b"\x6b",
        13: b"\x46",
        14: b"\x69",
        15: b"\x6c",
        16: b"\x65"
      }
    },
    {
      "name": "Audio Interchange File",
      "extension": "aif",
      "mime": "audio/x-aiff",
      "description": "",
      "magic_bytes": {
        0: b"\x46",
        1: b"\x4f",
        2: b"\x52",
        3: b"\x4d",
        8: b"\x41",
        9: b"\x49",
        10: b"\x46",
        11: b"\x46"
      }
    },
    {
      "name": "Audio Interchange File (compressed)",
      "extension": "aifc",
      "mime": "audio/x-aifc",
      "description": "",
      "magic_bytes": {
        0: b"\x46",
        1: b"\x4f",
        2: b"\x52",
        3: b"\x4d",
        8: b"\x41",
        9: b"\x49",
        10: b"\x46",
        11: b"\x43"
      }
    },
    {
      "name": "Portable Document Format",
      "extension": "pdf",
      "mime": "application/pdf",
      "description": "",
      "magic_bytes": {
        0: b"\x25",
        1: b"\x50",
        2: b"\x44",
        3: b"\x46"
      }
    },
    {
      "name": "Adobe PostScript",
      "extension": "ps,eps,ai,pfa",
      "mime": "application/postscript",
      "description": "",
      "magic_bytes": {
        0: b"\x25",
        1: b"\x21",
        2: b"\x50",
        3: b"\x53",
        4: b"\x2d",
        5: b"\x41",
        6: b"\x64",
        7: b"\x6f",
        8: b"\x62",
        9: b"\x65"
      }
    },
    {
      "name": "PostScript",
      "extension": "ps",
      "mime": "application/postscript",
      "description": "",
      "magic_bytes": {
        0: b"\x25",
        1: b"\x21"
      }
    },
    {
      "name": "Encapsulated PostScript",
      "extension": "eps,ai",
      "mime": "application/eps",
      "description": "",
      "magic_bytes": {
        0: b"\xc5",
        1: b"\xd0",
        2: b"\xd3",
        3: b"\xc6"
      }
    },
    {
      "name": "Rich Text Format",
      "extension": "rtf",
      "mime": "application/rtf",
      "description": "",
      "magic_bytes": {
        0: b"\x7b",
        1: b"\x5c",
        2: b"\x72",
        3: b"\x74"
      }
    },
    {
      "name": "Microsoft Office document/OLE2",
      "extension": "ole2,doc,xls,dot,ppt,xla,ppa,pps,pot,msi,sdw,db,vsd,msg",
      "mime": "application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint",
      "description": "Microsoft Office documents",
      "magic_bytes": {
        0: b"\xd0",
        1: b"\xcf",
        2: b"\x11",
        3: b"\xe0",
        4: b"\xa1",
        5: b"\xb1",
        6: b"\x1a",
        7: b"\xe1"
      }
    },
    {
      "name": "Microsoft Office 2007+ document",
      "extension": "docx,xlsx,pptx",
      "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "description": "",
      "magic_bytes": {
        38: b"\x5f",
        39: b"\x54",
        40: b"\x79",
        41: b"\x70",
        42: b"\x65",
        43: b"\x73",
        44: b"\x5d",
        45: b"\x2e",
        46: b"\x78",
        47: b"\x6d",
        48: b"\x6c"
      }
    },
    {
      "name": "Microsoft Access database",
      "extension": "mdb,mda,mde,mdt,fdb,psa",
      "mime": "application/msaccess",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x01",
        2: b"\x00",
        3: b"\x00",
        4: b"\x53",
        5: b"\x74",
        6: b"\x61",
        7: b"\x6e",
        8: b"\x64",
        9: b"\x61",
        10: b"\x72",
        11: b"\x64",
        12: b"\x20",
        13: b"\x4a",
        14: b"\x65",
        15: b"\x74"
      }
    },
    {
      "name": "Microsoft Access 2007+ database",
      "extension": "accdb,accde,accda,accdu",
      "mime": "application/msaccess",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x01",
        2: b"\x00",
        3: b"\x00",
        4: b"\x53",
        5: b"\x74",
        6: b"\x61",
        7: b"\x6e",
        8: b"\x64",
        9: b"\x61",
        10: b"\x72",
        11: b"\x64",
        12: b"\x20",
        13: b"\x41",
        14: b"\x43",
        15: b"\x45",
        16: b"\x20"
      }
    },
    {
      "name": "Microsoft OneNote document",
      "extension": "one",
      "mime": "application/onenote",
      "description": "",
      "magic_bytes": {
        0: b"\xe4",
        1: b"\x52",
        2: b"\x5c",
        3: b"\x7b",
        4: b"\x8c",
        5: b"\xd8",
        6: b"\xa7",
        7: b"\x4d",
        8: b"\xae",
        9: b"\xb1",
        10: b"\x53",
        11: b"\x78",
        12: b"\xd0",
        13: b"\x29",
        14: b"\x96",
        15: b"\xd3"
      }
    },
    {
      "name": "Outlook Express database",
      "extension": "dbx",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\xcf",
        1: b"\xad",
        2: b"\x12",
        3: b"\xfe",
        4: [
          b"\x30",
          b"\xc5",
          b"\xc6",
          b"\xc7"
        ],
        11: b"\x11"
      }
    },
    {
      "name": "Personal Storage Table (Outlook)",
      "extension": "pst,ost,fdb,pab",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x21",
        1: b"\x42",
        2: b"\x44",
        3: b"\x4e"
      }
    },
    {
      "name": "Microsoft Exchange Database",
      "extension": "edb",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        4: b"\xef",
        5: b"\xcd",
        6: b"\xab",
        7: b"\x89",
        8: [
          b"\x20",
          b"\x23"
        ],
        9: b"\x06",
        10: b"\x00",
        11: b"\x00",
        12: [
          b"\x00",
          b"\x01"
        ],
        13: b"\x00",
        14: b"\x00",
        15: b"\x00"
      }
    },
    {
      "name": "WordPerfect document",
      "extension": "wpd,wp,wp5,wp6,wpp,bk!,wcm",
      "mime": "application/wordperfect",
      "description": "",
      "magic_bytes": {
        0: b"\xff",
        1: b"\x57",
        2: b"\x50",
        3: b"\x43",
        7: [
          b"\x00",
          b"\x01",
          b"\x02"
        ],
        8: b"\x01",
        9: b"\x0a"
      }
    },
    {
      "name": "EPUB e-book",
      "extension": "epub",
      "mime": "application/epub+zip",
      "description": "",
      "magic_bytes": {
        0: b"\x50",
        1: b"\x4b",
        2: b"\x03",
        3: b"\x04",
        30: b"\x6d",
        31: b"\x69",
        32: b"\x6d",
        33: b"\x65",
        34: b"\x74",
        35: b"\x79",
        36: b"\x70",
        37: b"\x65",
        38: b"\x61",
        39: b"\x70",
        40: b"\x70",
        41: b"\x6c",
        42: b"\x69",
        43: b"\x63",
        44: b"\x61",
        45: b"\x74",
        46: b"\x69",
        47: b"\x6f",
        48: b"\x6e",
        49: b"\x2f",
        50: b"\x65",
        51: b"\x70",
        52: b"\x75",
        53: b"\x62",
        54: b"\x2b",
        55: b"\x7a",
        56: b"\x69",
        57: b"\x70"
      }
    },
    {
      "name": "JPG",
      "extension": "jpg,jpeg,jpe,thm,mpo",
      "mime": "image/jpeg",
      "description": "",
      "magic_bytes": {
        0: b"\xff",
        1: b"\xd8",
        2: b"\xff",
        3: [
          b"\xc0",
          b"\xc4",
          b"\xdb",
          b"\xdd",
          b"\xe0",
          b"\xe1",
          b"\xe2",
          b"\xe3",
          b"\xe4",
          b"\xe5",
          b"\xe7",
          b"\xe8",
          b"\xea",
          b"\xeb",
          b"\xec",
          b"\xed",
          b"\xee",
          b"\xfe"
        ]
      }
    },
    {
      "name": "GIF",
      "extension": "gif",
      "mime": "image/gif",
      "description": "",
      "magic_bytes": {
        0: b"\x47",
        1: b"\x49",
        2: b"\x46",
        3: b"\x38",
        4: [
          b"\x37",
          b"\x39"
        ],
        5: b"\x61"
      }
    },
    {
      "name": "PNG",
      "extension": "png",
      "mime": "image/png",
      "description": "",
      "magic_bytes": {
        0: b"\x89",
        1: b"\x50",
        2: b"\x4e",
        3: b"\x47",
        4: b"\x0d",
        5: b"\x0a",
        6: b"\x1a",
        7: b"\x0a"
      }
    },
    {
      "name": "WEBP",
      "extension": "webp",
      "mime": "image/webp",
      "description": "",
      "magic_bytes": {
        8: b"\x57",
        9: b"\x45",
        10: b"\x42",
        11: b"\x50"
      }
    },
    {
      "name": "Camera Image File Format",
      "extension": "crw",
      "mime": "image/x-canon-crw",
      "description": "",
      "magic_bytes": {
        6: b"\x48",
        7: b"\x45",
        8: b"\x41",
        9: b"\x50",
        10: b"\x43",
        11: b"\x43",
        12: b"\x44",
        13: b"\x52"
      }
    },
    {
      "name": "Canon CR2 raw image",
      "extension": "cr2",
      "mime": "image/x-canon-cr2",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x49",
          1: b"\x49",
          2: b"\x2a",
          3: b"\x00",
          8: b"\x43",
          9: b"\x52"
        },
        {
          0: b"\x4d",
          1: b"\x4d",
          2: b"\x00",
          3: b"\x2a",
          8: b"\x43",
          9: b"\x52"
        }
      ]
    },
    {
      "name": "TIF",
      "extension": "tif",
      "mime": "image/tiff",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x49",
          1: b"\x49",
          2: b"\x2a",
          3: b"\x00"
        },
        {
          0: b"\x4d",
          1: b"\x4d",
          2: b"\x00",
          3: b"\x2a"
        }
      ]
    },
    {
      "name": "BMP",
      "extension": "bmp",
      "mime": "image/bmp",
      "description": "",
      "magic_bytes": {
        0: b"\x42",
        1: b"\x4d",
        7: b"\x00",
        9: b"\x00",
        14: [
          b"\x0c",
          b"\x28",
          b"\x38",
          b"\x40",
          b"\x6c",
          b"\x7c"
        ],
        15: b"\x00",
        16: b"\x00",
        17: b"\x00"
      }
    },
    {
      "name": "JPEG Extended Range image",
      "extension": "jxr",
      "mime": "image/vnd.ms-photo",
      "description": "",
      "magic_bytes": {
        0: b"\x49",
        1: b"\x49",
        2: b"\xbc"
      }
    },
    {
      "name": "PSD",
      "extension": "psd",
      "mime": "image/vnd.adobe.photoshop",
      "description": "",
      "magic_bytes": {
        0: b"\x38",
        1: b"\x42",
        2: b"\x50",
        3: b"\x53",
        4: b"\x00",
        5: b"\x01",
        6: b"\x00",
        7: b"\x00",
        8: b"\x00",
        9: b"\x00",
        10: b"\x00",
        11: b"\x00"
      }
    },
    {
      "name": "Photoshop Large Document",
      "extension": "psb",
      "mime": "application/x-photoshop",
      "description": "",
      "magic_bytes": {
        0: b"\x38",
        1: b"\x42",
        2: b"\x50",
        3: b"\x53",
        4: b"\x00",
        5: b"\x02",
        6: b"\x00",
        7: b"\x00",
        8: b"\x00",
        9: b"\x00",
        10: b"\x00",
        11: b"\x00",
        12: b"\x00"
      }
    },
    {
      "name": "Paint Shop Pro image",
      "extension": "psp",
      "mime": "image/psp",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x50",
          1: b"\x61",
          2: b"\x69",
          3: b"\x6e",
          4: b"\x74",
          5: b"\x20",
          6: b"\x53",
          7: b"\x68",
          8: b"\x6f",
          9: b"\x70",
          10: b"\x20",
          11: b"\x50",
          12: b"\x72",
          13: b"\x6f",
          14: b"\x20",
          15: b"\x49",
          16: b"\x6d"
        },
        {
          0: b"\x7e",
          1: b"\x42",
          2: b"\x4b",
          3: b"\x00"
        }
      ]
    },
    {
      "name": "The GIMP image",
      "extension": "xcf",
      "mime": "image/x-xcf",
      "description": "",
      "magic_bytes": {
        0: b"\x67",
        1: b"\x69",
        2: b"\x6d",
        3: b"\x70",
        4: b"\x20",
        5: b"\x78",
        6: b"\x63",
        7: b"\x66",
        8: b"\x20",
        9: [
          b"\x66",
          b"\x76"
        ],
        10: [
          b"\x69",
          b"\x30"
        ],
        11: [
          b"\x6c",
          b"\x30"
        ],
        12: [
          b"\x65",
          b"\x31",
          b"\x32",
          b"\x33"
        ]
      }
    },
    {
      "name": "Icon image",
      "extension": "ico",
      "mime": "image/x-icon",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x00",
        2: b"\x01",
        3: b"\x00",
        4: [
          b"\x01",
          b"\x02",
          b"\x03",
          b"\x04",
          b"\x05",
          b"\x06",
          b"\x07",
          b"\x08",
          b"\x09",
          b"\x0a",
          b"\x0b",
          b"\x0c",
          b"\x0d",
          b"\x0e",
          b"\x0f",
          b"\x10",
          b"\x11",
          b"\x12",
          b"\x13",
          b"\x14",
          b"\x15"
        ],
        5: b"\x00",
        6: [
          b"\x10",
          b"\x20",
          b"\x30",
          b"\x40",
          b"\x80"
        ],
        7: [
          b"\x10",
          b"\x20",
          b"\x30",
          b"\x40",
          b"\x80"
        ],
        9: b"\x00",
        10: [
          b"\x00",
          b"\x01"
        ]
      }
    },
    {
      "name": "Radiance High Dynamic Range image",
      "extension": "hdr",
      "mime": "image/vnd.radiance",
      "description": "",
      "magic_bytes": {
        0: b"\x23",
        1: b"\x3f",
        2: b"\x52",
        3: b"\x41",
        4: b"\x44",
        5: b"\x49",
        6: b"\x41",
        7: b"\x4e",
        8: b"\x43",
        9: b"\x45",
        10: b"\x0a"
      }
    },
    {
      "name": "Sony ARW image",
      "extension": "arw",
      "mime": "image/x-raw",
      "description": "",
      "magic_bytes": {
        0: b"\x05",
        1: b"\x00",
        2: b"\x00",
        3: b"\x00",
        4: b"\x41",
        5: b"\x57",
        6: b"\x31",
        7: b"\x2e"
      }
    },
    {
      "name": "Fujifilm Raw Image",
      "extension": "raf",
      "mime": "image/x-raw",
      "description": "",
      "magic_bytes": {
        0: b"\x46",
        1: b"\x55",
        2: b"\x4a",
        3: b"\x49",
        4: b"\x46",
        5: b"\x49",
        6: b"\x4c",
        7: b"\x4d",
        8: b"\x43",
        9: b"\x43",
        10: b"\x44",
        11: b"\x2d",
        12: b"\x52",
        13: b"\x41",
        14: b"\x57"
      }
    },
    {
      "name": "Minolta RAW image",
      "extension": "mrw",
      "mime": "image/x-raw",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x4d",
        2: b"\x52",
        3: b"\x4d"
      }
    },
    {
      "name": "Adobe Bridge Thumbnail Cache",
      "extension": "bct",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x6c",
        1: b"\x6e",
        2: b"\x62",
        3: b"\x74",
        4: b"\x02",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Microsoft Document Imaging",
      "extension": "mdi",
      "mime": "image/vnd.ms-modi",
      "description": "",
      "magic_bytes": {
        0: b"\x45",
        1: b"\x50",
        2: b"\x2a",
        3: b"\x00"
      }
    },
    {
      "name": "AutoCAD Drawing",
      "extension": "dwg,123d",
      "mime": "application/acad",
      "description": "",
      "magic_bytes": {
        0: b"\x41",
        1: b"\x43",
        2: b"\x31",
        3: b"\x30",
        4: [
          b"\x30",
          b"\x31"
        ],
        5: [
          b"\x30",
          b"\x31",
          b"\x32",
          b"\x33",
          b"\x34",
          b"\x35"
        ],
        6: b"\x00"
      }
    },
    {
      "name": "AutoCAD Drawing",
      "extension": "dwg,dwt",
      "mime": "application/acad",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x41",
          1: b"\x43",
          2: b"\x31",
          3: b"\x30",
          4: b"\x31",
          5: b"\x38",
          6: b"\x00"
        },
        {
          0: b"\x41",
          1: b"\x43",
          2: b"\x31",
          3: b"\x30",
          4: b"\x32",
          5: b"\x34",
          6: b"\x00"
        },
        {
          0: b"\x41",
          1: b"\x43",
          2: b"\x31",
          3: b"\x30",
          4: b"\x32",
          5: b"\x37",
          6: b"\x00"
        }
      ]
    },
    {
      "name": "Targa Image",
      "extension": "tga",
      "mime": "image/x-targa",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x54",
          1: b"\x52",
          2: b"\x55",
          3: b"\x45",
          4: b"\x56",
          5: b"\x49",
          6: b"\x53",
          7: b"\x49",
          8: b"\x4f",
          9: b"\x4e",
          10: b"\x2d",
          11: b"\x58",
          12: b"\x46",
          13: b"\x49",
          14: b"\x4c",
          15: b"\x45",
          16: b"\x2e"
        }
      ]
    },
    {
      "name": "Matroska Multimedia Container",
      "extension": "mkv",
      "mime": "video/x-matroska",
      "description": "",
      "magic_bytes": {
        31: b"\x6d",
        32: b"\x61",
        33: b"\x74",
        34: b"\x72",
        35: b"\x6f",
        36: b"\x73",
        37: b"\x6b",
        38: b"\x61"
      }
    },
    {
      "name": "WEBM video",
      "extension": "webm",
      "mime": "video/webm",
      "description": "",
      "magic_bytes": {
        0: b"\x1a",
        1: b"\x45",
        2: b"\xdf",
        3: b"\xa3"
      }
    },
    {
      "name": "Flash MP4 video",
      "extension": "f4v",
      "mime": "video/mp4",
      "description": "",
      "magic_bytes": {
        4: b"\x66",
        5: b"\x74",
        6: b"\x79",
        7: b"\x70",
        8: [
          b"\x66",
          b"\x46"
        ],
        9: b"\x34",
        10: [
          b"\x76",
          b"\x56"
        ],
        11: b"\x20"
      }
    },
    {
      "name": "MPEG-4 video",
      "extension": "mp4",
      "mime": "video/mp4",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x00",
          1: b"\x00",
          2: b"\x00",
          3: [
            b"\x18",
            b"\x20"
          ],
          4: b"\x66",
          5: b"\x74",
          6: b"\x79",
          7: b"\x70"
        },
        {
          0: b"\x33",
          1: b"\x67",
          2: b"\x70",
          3: b"\x35"
        },
        {
          0: b"\x00",
          1: b"\x00",
          2: b"\x00",
          3: b"\x1c",
          4: b"\x66",
          5: b"\x74",
          6: b"\x79",
          7: b"\x70",
          8: b"\x6d",
          9: b"\x70",
          10: b"\x34",
          11: b"\x32",
          16: b"\x6d",
          17: b"\x70",
          18: b"\x34",
          19: b"\x31",
          20: b"\x6d",
          21: b"\x70",
          22: b"\x34",
          23: b"\x32",
          24: b"\x69",
          25: b"\x73",
          26: b"\x6f",
          27: b"\x6d"
        }
      ]
    },
    {
      "name": "M4V video",
      "extension": "m4v",
      "mime": "video/x-m4v",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x00",
        2: b"\x00",
        3: b"\x1c",
        4: b"\x66",
        5: b"\x74",
        6: b"\x79",
        7: b"\x70",
        8: b"\x4d",
        9: b"\x34",
        10: b"\x56"
      }
    },
    {
      "name": "Quicktime video",
      "extension": "mov",
      "mime": "video/quicktime",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x00",
        2: b"\x00",
        3: b"\x14",
        4: b"\x66",
        5: b"\x74",
        6: b"\x79",
        7: b"\x70"
      }
    },
    {
      "name": "Audio Video Interleave",
      "extension": "avi",
      "mime": "video/x-msvideo",
      "description": "",
      "magic_bytes": {
        0: b"\x52",
        1: b"\x49",
        2: b"\x46",
        3: b"\x46",
        8: b"\x41",
        9: b"\x56",
        10: b"\x49"
      }
    },
    {
      "name": "Windows Media Video",
      "extension": "wmv",
      "mime": "video/x-ms-wmv",
      "description": "",
      "magic_bytes": {
        0: b"\x30",
        1: b"\x26",
        2: b"\xb2",
        3: b"\x75",
        4: b"\x8e",
        5: b"\x66",
        6: b"\xcf",
        7: b"\x11",
        8: b"\xa6",
        9: b"\xd9"
      }
    },
    {
      "name": "MPEG video",
      "extension": "mpg",
      "mime": "video/mpeg",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x00",
        2: b"\x01",
        3: b"\xba"
      }
    },
    {
      "name": "Flash Video",
      "extension": "flv",
      "mime": "video/x-flv",
      "description": "",
      "magic_bytes": {
        0: b"\x46",
        1: b"\x4c",
        2: b"\x56",
        3: b"\x01"
      }
    },
    {
      "name": "OGG Video",
      "extension": "ogv,ogm,opus,ogx",
      "mime": "video/ogg",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x4f",
          1: b"\x67",
          2: b"\x67",
          3: b"\x53",
          4: b"\x00",
          5: b"\x02",
          28: b"\x01",
          29: b"\x76",
          30: b"\x69",
          31: b"\x64",
          32: b"\x65",
          33: b"\x6f"
        },
        {
          0: b"\x4f",
          1: b"\x67",
          2: b"\x67",
          3: b"\x53",
          4: b"\x00",
          5: b"\x02",
          28: b"\x80",
          29: b"\x74",
          30: b"\x68",
          31: b"\x65",
          32: b"\x6f",
          33: b"\x72",
          34: b"\x61"
        },
        {
          0: b"\x4f",
          1: b"\x67",
          2: b"\x67",
          3: b"\x53",
          4: b"\x00",
          5: b"\x02",
          28: b"\x66",
          29: b"\x69",
          30: b"\x73",
          31: b"\x68",
          32: b"\x65",
          33: b"\x61",
          34: b"\x64"
        }
      ]
    },
    {
      "name": "UTF-32 LE text",
      "extension": "utf32le",
      "mime": "charset/utf32le",
      "description": "Little-endian UTF-32 encoded Unicode byte order mark.",
      "magic_bytes": {
        0: b"\xff",
        1: b"\xfe",
        2: b"\x00",
        3: b"\x00"
      }
    },
    {
      "name": "UTF-16 LE text",
      "extension": "utf16le",
      "mime": "charset/utf16le",
      "description": "Little-endian UTF-16 encoded Unicode byte order mark.",
      "magic_bytes": {
        0: b"\xff",
        1: b"\xfe"
      }
    },
    {
      "name": "Web Open Font Format",
      "extension": "woff",
      "mime": "application/font-woff",
      "description": "",
      "magic_bytes": {
        0: b"\x77",
        1: b"\x4f",
        2: b"\x46",
        3: b"\x46",
        4: b"\x00",
        5: b"\x01",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Web Open Font Format 2",
      "extension": "woff2",
      "mime": "application/font-woff",
      "description": "",
      "magic_bytes": {
        0: b"\x77",
        1: b"\x4f",
        2: b"\x46",
        3: b"\x32",
        4: b"\x00",
        5: b"\x01",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Embedded OpenType font",
      "extension": "eot",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": [
        {
          8: b"\x02",
          9: b"\x00",
          10: b"\x01",
          34: b"\x4c",
          35: b"\x50"
        },
        {
          8: b"\x01",
          9: b"\x00",
          10: b"\x00",
          34: b"\x4c",
          35: b"\x50"
        },
        {
          8: b"\x02",
          9: b"\x00",
          10: b"\x02",
          34: b"\x4c",
          35: b"\x50"
        }
      ]
    },
    {
      "name": "TrueType Font",
      "extension": "ttf",
      "mime": "application/font-sfnt",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x01",
        2: b"\x00",
        3: b"\x00",
        4: b"\x00"
      }
    },
    {
      "name": "OpenType Font",
      "extension": "otf",
      "mime": "application/font-sfnt",
      "description": "",
      "magic_bytes": {
        0: b"\x4f",
        1: b"\x54",
        2: b"\x54",
        3: b"\x4f",
        4: b"\x00"
      }
    },
    {
      "name": "BitTorrent link",
      "extension": "torrent",
      "mime": "application/x-bittorrent",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x64",
          1: b"\x38",
          2: b"\x3a",
          3: b"\x61",
          4: b"\x6e",
          5: b"\x6e",
          6: b"\x6f",
          7: b"\x75",
          8: b"\x6e",
          9: b"\x63",
          10: b"\x65",
          11: b"\x23",
          12: b"\x23",
          13: b"\x3a"
        },
        {
          0: b"\x64",
          1: b"\x34",
          2: b"\x3a",
          3: b"\x69",
          4: b"\x6e",
          5: b"\x66",
          6: b"\x6f",
          7: b"\x64",
          8: [
            b"\x34",
            b"\x35",
            b"\x36"
          ],
          9: b"\x3a"
        }
      ]
    },
    {
      "name": "Cryptocurrency wallet",
      "extension": "wallet",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x00",
        2: b"\x00",
        3: b"\x00",
        4: b"\x01",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00",
        8: b"\x00",
        9: b"\x00",
        10: b"\x00",
        11: b"\x00",
        12: b"\x62",
        13: b"\x31",
        14: b"\x05",
        15: b"\x00"
      }
    },
    {
      "name": "Registry fragment",
      "extension": "hbin",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x68",
        1: b"\x62",
        2: b"\x69",
        3: b"\x6e",
        4: b"\x00"
      }
    },
    {
      "name": "Registry script",
      "extension": "rgs",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x48",
        1: b"\x4b",
        2: b"\x43",
        3: b"\x52",
        4: b"\x0d",
        5: b"\x0a",
        6: b"\x5c",
        7: b"\x7b"
      }
    },
    {
      "name": "WinNT Registry Hive",
      "extension": "registry",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x72",
        1: b"\x65",
        2: b"\x67",
        3: b"\x66"
      }
    },
    {
      "name": "Windows Event Log",
      "extension": "evt",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x30",
        1: b"\x00",
        2: b"\x00",
        3: b"\x00",
        4: b"\x4c",
        5: b"\x66",
        6: b"\x4c",
        7: b"\x65"
      }
    },
    {
      "name": "Windows Event Log",
      "extension": "evtx",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x45",
        1: b"\x6c",
        2: b"\x66",
        3: b"\x46",
        4: b"\x69",
        5: b"\x6c",
        6: b"\x65"
      }
    },
    {
      "name": "Windows Pagedump",
      "extension": "dmp",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x50",
        1: b"\x41",
        2: b"\x47",
        3: b"\x45",
        4: b"\x44",
        5: b"\x55",
        6: [
          b"\x4d",
          b"\x36"
        ],
        7: [
          b"\x50",
          b"\x34"
        ]
      }
    },
    {
      "name": "Windows Prefetch (Win 10)",
      "extension": "pf",
      "mime": "application/x-pf",
      "description": "",
      "magic_bytes": {
        0: b"\x4d",
        1: b"\x41",
        2: b"\x4d",
        3: b"\x04",
        7: b"\x00"
      }
    },
    {
      "name": "PList (binary)",
      "extension": "bplist,plist,ipmeta,abcdp,mdbackup,mdinfo,strings,nib,ichat,qtz,webbookmark,webhistory",
      "mime": "application/x-plist",
      "description": "",
      "magic_bytes": {
        0: b"\x62",
        1: b"\x70",
        2: b"\x6c",
        3: b"\x69",
        4: b"\x73",
        5: b"\x74",
        6: b"\x30",
        7: b"\x30"
      }
    },
    {
      "name": "MacOS X Keychain",
      "extension": "keychain",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x6b",
        1: b"\x79",
        2: b"\x63",
        3: b"\x68",
        4: b"\x00",
        5: b"\x01"
      }
    },
    {
      "name": "TCP Packet",
      "extension": "tcp",
      "mime": "application/tcp",
      "description": "",
      "magic_bytes": {
        12: b"\x08",
        13: b"\x00",
        14: b"\x45",
        15: b"\x00",
        21: b"\x00",
        23: b"\x06"
      }
    },
    {
      "name": "UDP Packet",
      "extension": "udp",
      "mime": "application/udp",
      "description": "",
      "magic_bytes": {
        12: b"\x08",
        13: b"\x00",
        14: b"\x45",
        15: b"\x00",
        16: [
          b"\x00",
          b"\x01",
          b"\x02",
          b"\x03",
          b"\x04",
          b"\x05"
        ],
        23: b"\x11"
      }
    },
    {
      "name": "Compiled HTML",
      "extension": "chm,chw,chi",
      "mime": "application/vnd.ms-htmlhelp",
      "description": "",
      "magic_bytes": {
        0: b"\x49",
        1: b"\x54",
        2: b"\x53",
        3: b"\x46",
        4: b"\x03",
        5: b"\x00",
        6: b"\x00",
        7: b"\x00"
      }
    },
    {
      "name": "Windows Password",
      "extension": "pwl",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\xe3",
        1: b"\x82",
        2: b"\x85",
        3: b"\x96"
      }
    },
    {
      "name": "Bitlocker recovery key",
      "extension": "bitlocker",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\xff",
        1: b"\xfe",
        2: b"\x42",
        3: b"\x00",
        4: b"\x69",
        5: b"\x00",
        6: b"\x74",
        7: b"\x00",
        8: b"\x4c",
        9: b"\x00",
        10: b"\x6f",
        11: b"\x00",
        12: b"\x63",
        13: b"\x00",
        14: b"\x6b",
        15: b"\x00",
        16: b"\x65",
        17: b"\x00",
        18: b"\x72",
        19: b"\x00",
        20: b"\x20",
        21: b"\x00"
      }
    },
    {
      "name": "Certificate",
      "extension": "cer,cat,p7b,p7c,p7m,p7s,swz,rsa,crl,crt,der",
      "mime": "application/pkix-cert",
      "description": "",
      "magic_bytes": {
        0: b"\x30",
        1: b"\x82",
        4: [
          b"\x06",
          b"\x0a",
          b"\x30"
        ]
      }
    },
    {
      "name": "Certificate",
      "extension": "cat,swz,p7m",
      "mime": "application/vnd.ms-pki.seccat",
      "description": "",
      "magic_bytes": {
        0: b"\x30",
        1: b"\x83",
        5: b"\x06",
        6: b"\x09"
      }
    },
    {
      "name": "PGP pubring",
      "extension": "pkr,gpg",
      "mime": "application/pgp-keys",
      "description": "",
      "magic_bytes": {
        0: b"\x99",
        1: b"\x01",
        2: [
          b"\x0d",
          b"\xa2"
        ],
        3: b"\x04"
      }
    },
    {
      "name": "PGP secring",
      "extension": "skr",
      "mime": "application/pgp-keys",
      "description": "",
      "magic_bytes": [
        {
          0: b"\x95",
          1: b"\x01",
          2: b"\xcf",
          3: b"\x04"
        },
        {
          0: b"\x95",
          1: b"\x03",
          2: b"\xc6",
          3: b"\x04"
        }
      ]
    },
    {
      "name": "PGP Safe",
      "extension": "pgd",
      "mime": "application/pgp-keys",
      "description": "",
      "magic_bytes": {
        0: b"\x50",
        1: b"\x47",
        2: b"\x50",
        3: b"\x64",
        4: b"\x4d",
        5: b"\x41",
        6: b"\x49",
        7: b"\x4e",
        8: b"\x60",
        9: b"\x01",
        10: b"\x00"
      }
    },
    {
      "name": "Task Scheduler",
      "extension": "job",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: [
          b"\x00",
          b"\x01",
          b"\x02",
          b"\x03"
        ],
        1: [
          b"\x05",
          b"\x06"
        ],
        2: b"\x01",
        3: b"\x00",
        20: b"\x46",
        21: b"\x00"
      }
    },
    {
      "name": "Windows Shortcut",
      "extension": "lnk",
      "mime": "application/x-ms-shortcut",
      "description": "",
      "magic_bytes": {
        0: b"\x4c",
        1: b"\x00",
        2: b"\x00",
        3: b"\x00",
        4: b"\x01",
        5: b"\x14",
        6: b"\x02",
        7: b"\x00",
        8: b"\x00",
        9: b"\x00",
        10: b"\x00",
        11: b"\x00",
        12: b"\xc0",
        13: b"\x00",
        14: b"\x00",
        15: b"\x00",
        16: b"\x00",
        17: b"\x00",
        18: b"\x00",
        19: b"\x46"
      }
    },
    {
      "name": "Smile",
      "extension": "sml",
      "mime": " application/x-jackson-smile",
      "description": "",
      "magic_bytes": {
        0: b"\x3a",
        1: b"\x29",
        2: b"\x0a"
      }
    },
    {
      "name": "Lua Bytecode",
      "extension": "luac",
      "mime": "application/x-lua",
      "description": "",
      "magic_bytes": {
        0: b"\x1b",
        1: b"\x4c",
        2: b"\x75",
        3: b"\x61"
      }
    },
    {
      "name": "WebAssembly binary",
      "extension": "wasm",
      "mime": "application/octet-stream",
      "description": "",
      "magic_bytes": {
        0: b"\x00",
        1: b"\x61",
        2: b"\x73",
        3: b"\x6d"
      }
    }
  ]
}

def fp_match(magic_bytes, data):
    is_matching = True
    for pos, fp_bytes in magic_bytes.items(): 
        if pos >= len(data): 
          return False
        is_matching &= (data[pos] in fp_bytes)
    return is_matching

def strict_match(dtype, data):
  if dtype in fp_list.keys(): 
    for data_type in fp_list[dtype] : 
      is_matching = False
      if "magic_bytes" in data_type : 
        m_bytes = data_type["magic_bytes"]
        if isinstance(m_bytes, dict): 
          is_matching = fp_match(m_bytes, data)
        elif isinstance(m_bytes, list): 
          for magic in m_bytes: 
            is_matching |= fp_match(magic, data)

      if is_matching : 
        return data_type.get("name")

  return False

def contain_match(dtype, data):
  if dtype in fp_list.keys(): 
    for data_type in fp_list[dtype] : 
      if "regex" in data_type :
        if re.match(data_type["regex"], data): 
          return data_type.get("name")

  return False

def match(dtype, data): 
  type_name = strict_match(dtype, data)
  if type_name :
    return type_name
  else : 
    type_name = contain_match(dtype, data)
    if type_name: 
      return f'{type_name} inside data'

  return False