"""
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

mascot = rf""" 
                                                                                                                           "$%'()*+++16.-/,)%             
                                                                                                             "%*07@HNV\`ccc_\ZX[ZUTTV\`[WVPKJ; 
                                                                                                  &-6>JU`iqw)¨°µ³«~pcaOVRLJJQ[cQLptssnf^UKC?@4   
                                                         '6<=860)$                         *8G[kzª·ÁÉÌÐÒÒÐËÃµ¨whYOJHJFDJJO[itwjV)z`SKD@><<=?6#            
                                                         )P__^a`^YQG;.&!             +<Ri~²ÆÑ×ÜàââÝÔÍÃ½²§ypib^[VTOKIGGFEGJQRMGDJG<9999:;=?;+              
                                                          )JNTTSOOUXYXTLD?3("  %4Li¥»ÌÚâåæêáà×ËÁ¸²§¡zunkjjid\RJEEEFDA?<:;99668899<=?>>?@9,"               
                                                           2FHMLFDFHGM[qo·²¸µª²ÀÐÚãèêìëëÜÝ¿ÆÌ°§¡zqkfb_[XUOGAAFNPOLGDFGKOOXR^SPD=<5<GMD7*                  
                                                           %AEDDEGEHbn¢·ÃÉÏÎÕÚÝÞáçêæèÏåÀÃÁxµ¡ri`ZTPLIDA??BJW`fioy©´»¾¼¹µ­£tk^TKDCEJ;0$                    
                                                            0ADCKGnq»ÂÑÆÓÓÔ×ÊÚÝÀ»ÆÅÉ¾³µli`UGEGGDA?<9:?FNYadfinrtqnib[TMHD?<:99;?EE,                       
                                                             ;JQj²ÅÚÌÈÃÏ×·Ù²âë¾Lazoc]MGG=@B98:9999AJMOPONLJJHEC@><:987777789<?A=0"                        
                                                            (Vv¿ÑÓÇ¾Æ½ÀË²ªÆÉÕ®gOO^^RJB<?:8:934668:=@DDA@><<:9988777776668<AD?0%                           
                                                          !O¶ÅÔ×ÄÆ½¦×u½Ñ±®Æ¬dRU\KKNH@A:7;66:?<98<<<;:99998887776666669<AD?3'                              
                                                        4R¸ÖÏÌÑÃËs¹wÌo­°­t_QXeyhQ;<:633369:99;::999988887776666679<?AA;0%                                 
                                                     +?¥¼Ö×ÍµÓ§©´i­i¯yqiRFUz¯©pWG8--.013688898888777666666669;?ACA:0("                                    
                                                  "Cn¸ÍÝµâÐw±Äw¦¬hqgcZOKSm)pWB853446778888877776666666678:=A@=6/&                 """rf"""{Color.AQUA}____  o             ___  _             _  {Color.END}                   
                                                +R·Àá»Ú±º»ª¡¤­lxkaXWUX[XOB623568899888887766666666679:<<=<99."                    """rf"""{Color.AQUA} ))   _  ___  __ __ ))_  ))_  ___  __  )L,{Color.END}
                                             #Ez¸ÒÀÆ¿¨Êo®££qgn`_[[XPG?97789999999888887676676789:;<<;999999886-!                  """rf"""{Color.AQUA}((   (( ((_( (('(|  _(( ((`( ((_( (|  ((\ {Color.END}
      ":>6*"                               0T²»º¹Àh¥zz¨fnfcc`\TJA9533332123345678888877889;<=>=<;9989999::;<<:;4'                 """rf"""{Color.AQUA}          _))                             {Color.END}
       )AKQSOB3%                     /LP>BtªÀ²zfin^_iaf^[WOD<6323332333456667888999:<?ABA?84889:;<<====<<<<<<<;;:.  
        ):>DLV`d]K6#                (Y»èÊ¾¼`b[SXJ][\[SI?631345445667889999999;=?BEFC@91)$    "#$%')+/3589;<<<<<<<;8# 
         +17=AHOZjttgL0            #ZµÅ­_cGEECQXOKD<53346667788899999::<=?BDFEDA70("                   "%(.269<<<<>4 
           $3<>CJOVas¨²¥^4       %M~²d\C?DJEID?976677656786326:;;<<=?@CB@<60)$                              $*069;:9$ 
            !)39=AHOT^o¨ÃÏ­O&  *UtpVC<;AC??=;<<<<<9:DP[ZM?:;=====>???A=#                                       %,368%  
              !+39<?EKQ]nªÆØÊbE^UA><@>==<<>?AAACA?e°¾©\@69999999999989*                                          #*& 
                "*17;?DL\u£zlWA>9=<>>>>==?=4.+))9£µo?#   "#$%(-2689896" 
                  !)068EYWE98;?@BCD<899<;0"    0XH%             #*046, 
                     '04679;<<?;1-("!,E9'      $                   "&! 
                      !,36;<<96"     &3! 
                        .59<;6( 
                        %89:5* 
                         065,!                                                                                                                 
                         ,3."                       
                        !00$                                                                                                         
                        !+"                         
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


___               __               
 |  o  _   _  ._ (_  |_   _. ._ |  
 |  | (_| (/_ |  __) | | (_| |  |< 
       _|                          

 _______ ,-.   ,--,    ,---.   ,---.       .---.  .-. .-.   .--.   ,---.    ,-. .-. 
|__   __||(| .' .'     | .-'   | .-.\     ( .-._) | | | |  / /\ \  | .-.\   | |/ /  
  )| |   (_) |  |  __  | `-.   | `-'/    (_) \    | `-' | / /__\ \ | `-'/   | | /   
 (_) |   | | \  \ ( _) | .-'   |   (     _  \ \   | .-. | |  __  | |   (    | | \   
   | |   | |  \  `-) ) |  `--. | |\ \   ( `-'  )  | | |)| | |  |)| | |\ \   | |) \  
   `-'   `-'  )\____/  /( __.' |_| \)\   `----'   /(  (_) |_|  (_) |_| \)\  |((_)-' 
             (__)     (__)         (__)          (__)                  (__) (_)     

____          
 L| iger((hark
        '' 

 _______ _____  ______ _______  ______ _______ _     _ _______  ______ _     _
    |      |   |  ____ |______ |_____/ |______ |_____| |_____| |_____/ |____/ 
    |    __|__ |_____| |______ |    \_ ______| |     | |     | |    \_ |    \_

 ______                                    ____        __                           __         
/\__  _\   __                             /\  _`\     /\ \                         /\ \        
\/_/\ \/  /\_\      __        __    _ __  \ \,\L\_\   \ \ \___       __      _ __  \ \ \/'\    
   \ \ \  \/\ \   /'_ `\    /'__`\ /\`'__\ \/_\__ \    \ \  _ `\   /'__`\   /\`'__\ \ \ , <    
    \ \ \  \ \ \ /\ \L\ \  /\  __/ \ \ \/    /\ \L\ \   \ \ \ \ \ /\ \L\.\_ \ \ \/   \ \ \\`\  
     \ \_\  \ \_\\ \____ \ \ \____\ \ \_\    \ `\____\   \ \_\ \_\\ \__/.\_\ \ \_\    \ \_\ \_\
      \/_/   \/_/ \/___L\ \ \/____/  \/_/     \/_____/    \/_/\/_/ \/__/\/_/  \/_/     \/_/\/_/
                    /\____/                                                                    
                    \_/__/                                                                     

 _______  __                      _______  __                  __    
|_     _||__|.-----..-----..----.|     __||  |--..---.-..----.|  |--.
  |   |  |  ||  _  ||  -__||   _||__     ||     ||  _  ||   _||    < 
  |___|  |__||___  ||_____||__|  |_______||__|__||___._||__|  |__|__|
             |_____|                                                 

 ______  ____   ____    ___  ____    _____ __ __   ____  ____   __  _ 
|      Tl    j /    T  /  _]|    \  / ___/|  T  T /    T|    \ |  l/ ]
|      | |  T Y   __j /  [_ |  D  )(   \_ |  l  |Y  o  ||  D  )|  ' / 
l_j  l_j |  | |  T  |Y    _]|    /  \__  T|  _  ||     ||    / |    \ 
  |  |   |  | |  l_ ||   [_ |    \  /  \ ||  |  ||  _  ||    \ |     Y
  |  |   j  l |     ||     T|  .  Y \    ||  |  ||  |  ||  .  Y|  .  |
  l__j  |____jl___,_jl_____jl__j\_j  \___jl__j__jl__j__jl__j\_jl__j\_j

 _____  _                  ___  _                _   
|_   _|(_) __ _  ___  _ _ / __|| |_   __ _  _ _ | |__
  | |  | |/ _` |/ -_)| '_|\__ \| ' \ / _` || '_|| / /
  |_|  |_|\__, |\___||_|  |___/|_||_|\__,_||_|  |_\_\
          |___/                                      

 _____   ___   ____   ___   ____    ___   _  _     _    ____   _  _  
)__ __( )_ _( ).-._( ) __( /  _ \  (  _( ) () (   )_\  /  _ \ ) |) / 
  | |   _| |_ |( ,-. | _)  )  ' /  _) \  | -- |  /( )\ )  ' / | ( (  
  )_(  )_____()_`__( )___( |_()_\ )____) )_()_( )_/ \_(|_()_\ )_|)_\ 

~|~.   _   (`|_    | 
 | |(|(/_|`_)||(||`|<
    _|               

____  o             ___  _             _  
 ))   _  ___  __ __ ))_  ))_  ___  __  )L,
((   (( ((_( (('(|  _(( ((`( ((_( (|  ((\ 
          _))                             

"""
