########################################################################
#                NetSec II - Project : MitM                            #
########################################################################

########################################################################
# Name: mitm                       Version: 1.0                        #
# Goal: Man in the Middle software                                     #
########################################################################

########################################################################
# Software goals: The program must do a network scan, and allow the    #
# user to do man in the middle attacks on specified target(s) or on a  #
# whole ip range.                                                      #
# It must be able to bypass https connections (2 methods mandatory),   #
# alter victims' data and log the network activities during the attack #
# and going throug itself.                                             #
########################################################################

########################################################################
# Mandatory Features:                                                  #
# - CLI or curses                                                      #
# - automated mitm for every host found with a predefined gate or host #
# - 2 scan types: open/semi-open                                       #
# - 2 types of ssl-bypass: fake-https / non-https                      #
# - regexp session definition                                          #
# - session stealing and usage through proxy                           #
# - journalized logs (url, cookies, ...) with date and time            #
# - data injection:                                                    #
#   - on-the-fly vitcim's content modification                         #
#   - on-the-fly victim's url modification (one shot or automated with #
#   regexp)                                                            #
########################################################################