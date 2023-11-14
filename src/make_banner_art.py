"""  # pylint: disable=line-too-long
This module contains the functionality for generating a decorative banner art for a Python-based TShark wrapper
application. The banner art, created using various ASCII characters and symbols, adds a unique and creative touch
to the command-line interface of the application.

Author: 4u7h0r (80y13)
Created: July 2023

Purpose:
The module is part of a larger Python wrapper over TShark, which allows users to analyze PCAP files through a
user-friendly command-line interface. It enhances user experience by providing a visually appealing banner at
the start of the application.

Usage:
The `banner` variable, defined as a raw formatted string, can be printed to the console to display the art. It
includes colorful elements and symbols to create an engaging visual.

Dependencies:
- The module relies on the `make_colorful` module for colorizing certain parts of the banner.

Compatibility:
This script is compatible with WSL2 Ubuntu, macOS, and other Unix-like systems.

Note:
The script provides references to Wireshark display filter documentation and sources for downloading PCAP files.
It's designed to be part of a larger application that provides network packet analysis functionalities.

This module is purely for aesthetic purposes and does not contain any functional logic related to packet analysis.
"""

from make_colorful import Color


banner = rf"""
{Color.BLUE}██▓▒░⡷⠂♦¯`v^♦·●·-•°•.•°••°•.•°•🌨❄•°•.•°• ⚡️¯\_༼ ಥ ‿ ಥ ༽_/¯⚡ •°•.•°•❄🌨️•°•.•°••°•.•°•-·●·♦^v¯`♦⠐⢾░▒▓██{Color.END}

     _.-----._
   .'          '.  *    4u7h0r: (80y13
  /              \/*
 |                |     (r3473d: Ju1y, 2023
|.-.           _.-.|
|| |          |   ||    7h!5 !5 4 Py7h0n wr4pp3r 0v3r 75h4rk wh!(h 1375 y0u hun7 7hr0u9h 4 P(4P f!13.
|| |   -:-    |   ||
|| |.-'-' '-.-|   ||    7h!5 5(r!p7 w!11 f!r57 45k f0r 7h3 fu11 p47h 70 7h3 P(4P f!13.
 \__|        \__/
  L__\        /__J      {Color.MAROON}((*´_●｀☆ﾟ+. 🎧♪┏(°.°)┛🎼 🎼┏(°.°)┛♪🎧 .+ﾟ☆´●_｀*)){Color.END}
   |__\      /__|
   L__|'-.-'|__J        W!r35h4rk d!5p14y f!173r r3f3r3n(3:  https://www.wireshark.org/docs/dfref/
    |__|   |__|
    L__|'-'|__J         P(4P5 (4n 83 d0wn104d3d fr0m:  https://www.malware-traffic-analysis.net/
     |__| |__|
     L__|_|__J          7h!5 5(r!p7 w0rk5 0n: W512 U8un7u, 4nd M4(05
      \__|__/
        \__/                                       \/\_/\/
      _.-'Y'-._                                    ( o.o )
     '--. || .--'                                   > ^ <
          |||
         (.-.)          Pr3r3qu!5!735:   ❄•°•.•°• W!r35h4rk •°•.•°•❄
       -"\/"\/""-
"""


r"""
['◄[🏆]► ''⚡️¯\\_༼ ಥ ‿ ಥ ༽_/¯⚡','' ◄[🥇]►']
██▓▒░⡷⠂♦¯`v^♦·●·-🌨❄•°•.•°• ⚡️¯\_༼ ಥ ‿ ಥ ༽_/¯⚡ •°•.•°•❄🌨️-·●·♦^v¯`♦⠐⢾░▒▓██
٩(●̮̮̃•̃)=/̵͇̿̿/'̿̿ ̿̿  ̿̿ ̿̿ ̿̿\̵͇̿̿\=(•̃●̮̮̃)۶
(★)(¯`·.●.● ●.●.·¯)(★)
＼＼\(۶•̀ᴗ•́)۶//／／ \\٩(•́⌄•́๑)و////
🎧♪┏(°.°)┛🎼 🎼┏(°.°)┛♪🎧
((*´_●｀☆ﾟ+. 🎧♪┏(°.°)┛🎼 🎼┏(°.°)┛♪🎧 .+ﾟ☆´●_｀*))
(◦′ᆺ‵◦) ♬° ✧❥✧¸.•*¨*✧♡✧ ✧♡✧*¨*•.❥
··●(`●- -●´)●··
ヽ༼ ಠ益ಠ ༽ﾉ
t(-.-t)
ლ(ಠ益ಠ)ლ
♚ ♛ ♜ ♝ ♞ ♟ ♔ ♕ ♖ ♗ ♘ ♙
(╯°□°)╯︵ ɹoɹɹƎ  ლ(ಠ益ಠლ)
ᕙ(⇀‸↼‶)ᕗ
ヾ(´〇`)ﾉ♪♪♪
̿'̿'\̵͇̿̿\з=( ͡ °_̯͡° )=ε/̵͇̿̿/'̿'̿ ̿
¯¯̿̿¯̿̿'̿̿̿̿̿̿̿'̿̿'̿̿̿̿̿'̿̿̿)͇̿̿)̿̿̿̿ '̿̿̿̿̿̿\̵͇̿̿\=(•̪̀●́)=o/̵͇̿̿/'̿̿ ̿ ̿̿
̿' ̿'\̵͇̿̿\з=(◕_◕)=ε/̵͇̿̿/'̿'̿ ̿
̿̿ ̿̿ ̿’̿̿’̿\̵͇̿̿\з=( ͡ °_̯͡° )=ε/̵͇̿̿/’̿̿’̿ ̿ ̿̿ ̿̿
(•̪●)=ε/̵͇̿̿/’̿’̿ ̿ ̿̿ ̿ ̿””
̿̿ ̿̿ ̿̿ ̿'̿'\̵͇̿̿\з=( ͠° ͟ʖ ͡°)=ε/̵͇̿̿/'̿̿ ̿ ̿ ̿ ̿ ̿
"""
