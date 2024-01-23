#!/bin/bash
 
######################################################################################################
#                                                                                                    #
# crypto.sh                                                                                          #
# @version                 0.2nightly                                                                #
# @date                    26.07.2015                                                                #
# @author                  Tobi <tobster@brain-force.ch>                                             #
# @license                 Open Source (GPLv3)                                                       #
# @depends                 Bash                                                                      #
#                          OpenSSL                                                                   #
# @abstract                bash wrapper script for en/de-cryption with openssl                       #
#                          it takes at least an action argument and a path to file                   #
#                          then action will be performed on file.                                    #
# @example                 crypto.sh enc -f /path/to/file                                            #
# @arguments               see crypto.sh -h|--help for more information on available parameters      #
# @latest changes          * use cat and redirection instead of mv to preserve the original ACL      #
#                          * added static config variables for openssl binary and temp dir           #
#                          * added sha256 as default password digest. See ticket:                    #
#                            https://project.brain-force.ch/openssl-crypt/ticket/1                   #
#                          * added possibility to harden encryption password by performing x rounds  #
#                            of digest hash on the password given. See ticket:                       #
#                            https://project.brain-force.ch/openssl-crypt/ticket/2                   #
#                          * make it harder to guess the temp file name by using 32 chars from       #
#                            urandom added to the original filename                                  #
#                          * supports scrypt hash function to create encryption password. See:       #
#                            https://project.brain-force.ch/openssl-crypt/ticket/3                   #
#                          * added a switch -s|--scrypt to enable usage of scrypt                    #
#                          * path to python interpreter now configurable via $PYTHON variable        #
#                          * added digests: ripemd160, whirlpool, sha224 and sha384                  #
#                          * use python-wrapper (crypt.py) instead of directly call openssl          #
#                            <fix>: https://project.brain-force.ch/openssl-crypt/ticket/7            #
#                          * ask for user confirmation if no rounds for hashing are specified        #
#                          * new ways to provide passwords:                                          #
#                            * path to a file can be given via -p|--password parameter               #
#                              the first line from that file is used as password                     #
#                            * password can be given interactive                                     #
#                              just ommit the -p|--password parameter to be prompted for password    #
#                          * code restructure                                                        #
#                                                                                                    #
######################################################################################################
 
#Define static vars
VERSION='0.2nightly'
TMP_DIR=/tmp/test
OPENSSL=/usr/bin/openssl
ROUNDS=1
DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
PYTHON=$(which python)
SCRIPT=$(basename ${BASH_SOURCE[0]})
NORM=`tput sgr0`
BOLD=`tput bold`
REV=`tput smso`
QUIET=''
VERBOSE=0


function do_printMessage() {
 DATE="$(date +'%b %d %H:%M:%S.%3N') $(hostname) $(basename $0)[$$]: ($(whoami)):"
 PREFIX='INFO'
 if [[ "x$QUIET" != 'x' && $QUIET -eq 1 ]] ; then
  [ $# -ne 3 ] && exit 255
  [ $3 -ge 0 ] && exit $3
 elif [[ "x$QUIET" != 'x' && $QUIET -eq 0 ]] ; then
  [ $# -ne 3 ] && exit 255
  [ $3 -ge 0 ] && exit $3 
 elif [ $VERBOSE -eq 0 ] ; then
  [ $# -ne 3 ] && echo "$DATE FATAL: do_printMessage() requires exactly 3 arguments" && exit 255
  PREFIX="$1"
  [[ $3 -ge 0 && "$PREFIX" != 'INFO' ]] && echo "$DATE $PREFIX: $2" && exit $3
  [ "$PREFIX" != 'INFO' ] && echo "$DATE $PREFIX: $2"
 else
  [ $# -ne 3 ] && echo "$DATE FATAL: do_printMessage() requires exactly 3 arguments" && exit 255
  PREFIX="$1"
  [ $3 -ge 0 ] && echo "$DATE $PREFIX: $2" && exit $3
  echo "$DATE $PREFIX: $2"
 fi
}

function do_showParams() {
   if [ "$1" == 'digest' ] ; then
     i=1
	   for c in $(openssl list-message-digest-algorithms|egrep '^.+\s='|sort -n|awk -F' => ' '{print $1"=>"$2}') ; do
	      if [[ $(($i % 4)) -eq 0 && $i -ne 0 ]] ; then
	        AliasDigestString="${AliasDigestString}${c}\n"
	      else
	        AliasDigestString="${AliasDigestString}${c}\t"
	      fi
	    i=$(($i + 1))
	   done
	   i=1
	   for c in $(openssl list-message-digest-algorithms|egrep -v '^.+\s='|sort -n) ; do
	     if [[ $(($i % 4)) -eq 0 && $i -ne 0 ]] ; then
          DigestString="${DigestString}$(echo ${c}|perl -ne 'chomp and print')\n"
        else
          DigestString="${DigestString}$(echo ${c}|perl -ne 'chomp and print')\t"
        fi
      i=$(($i + 1))
     done
   elif [ "$1" == 'cipher' ] ; then
	   i=1
	   for c in $(openssl list-cipher-algorithms|egrep '^.+\s='|sort -n |awk -F' => ' '{print $1"=>"$2}') ; do
	    if [[ $(($i % 3)) -eq 0 && $i -ne 0 ]] ; then
	      AliasCipherString="${AliasCipherString}${c}\n"
	    else
	      AliasCipherString="${AliasCipherString}${c}\t"
	      # break
	    fi
	    i=$(($i + 1))
	   done
	   i=1
	   for c in $(openssl list-cipher-algorithms|egrep -v '^.+\s='|sort -n) ; do
	    if [[ $(($i % 6)) -eq 0 && $i -ne 0 ]] ; then
	      CipherString="${CipherString}$(echo ${c}|perl -ne 'chomp and print')\n"
	    else
	      CipherString="${CipherString}$(echo ${c}|perl -ne 'chomp and print') "
	      # break
	    fi
	    i=$(($i + 1))
	   done
   fi
}


function do_showHelp() {
 echo -e \\n"Help documentation for ${BOLD}${SCRIPT}.${VERSION}.${NORM}"\\n
 if [ "x$ACTION" = 'x' ] ; then
  echo -e "  ${BOLD}${SCRIPT}${NORM} ACTION -f|--file -p|--pass [[-c|--cipher] blowfish] [[-d|--digest] sha256] [[-r|--rounds 1] [-s|--scrypt 0] [[-k|--keysize] 256] [--quiet] [--verbose] [--show] [--force]${NORM}"
  echo -e "    Positional ACTION  argument is ${BOLD}mandatory${NORM} and must be ${BOLD}the first argument${NORM}"
  echo -e "    Possible values for ACTION$ are: ${BOLD}enc${NORM}|${BOLD}dec${NORM}|${BOLD}dec-write${NORM}|${BOLD}dec-disp${NORM}"
  echo -e "  ${REV}WARNING: the enc parameter encrypts FILE and overwrites the unencrypted file with the crypted content${NORM}"
  echo -e "  Most command line switches are optional. The following switches are recognized"
  echo -e "    ${BOLD}-f|--file${NORM}    <string>    --file to perform ACTION on"
  echo -e "                               ${BOLD}mandatory, no default${NORM}"
  echo -e "    ${BOLD}-p|--pass${NORM}    <string>    --password to use as key for encryption"
  echo -e "                               ${BOLD}mandatory, no default${NORM}"
  echo -e "    ${BOLD}-c|--cipher${NORM}  <string>    --cipher to use for encryption"
  echo -e "                               ${BOLD}not mandatory, blowfish${NORM}"
  echo -e "    ${BOLD}-d|--digest${NORM}  <string>    --digest to use for file content hashing and for hashing the password with"
  echo -e "                               ${BOLD}not mandatory, sha256${NORM}" 
  echo -e "    ${BOLD}-k|--keysize${NORM} <string>    --size of the encryption key to generate in bits"
  echo -e "                               ${BOLD}not mandatory, 256${NORM}" 
  echo -e "    ${BOLD}-r|--rounds${NORM}  <integer>   --number of rounds to apply digest to the password"
  echo -e "                               ${BOLD}not mandatory, 1${NORM}"
  echo -e "    ${BOLD}-s|--scrypt${NORM}  <integer>   --use scrypt for password hashing as well. run hash function X times"
  echo -e "                               ${BOLD}not mandatory, 0${NORM}"
  echo -e "    ${BOLD}-h|--help${NORM}    <NONE>      --displays this help message"
  echo -e "                               ${BOLD}not mandatory${NORM}"
  echo -e "    ${BOLD}-v|--version${NORM} <NONE>      --shows version information"
  echo -e "                               ${BOLD}not mandatory${NORM}"
  echo -e "    ${BOLD}--show${NORM}       <NONE>      --show available ciphers from openssl"
  echo -e "                               ${BOLD}not mandatory${NORM}"
  echo -e "    ${BOLD}--force${NORM}      <NONE>      --enforces decryption even if the decryptet content looks compromised"
  echo -e "                               ${BOLD}not mandatory${NORM}"
  echo -e "    ${BOLD}--quiet${NORM}      <integer>   --supress ANY output if set to 1. Just exit with return codes. Helpful for scripts" 
  echo -e "                               If set to 0 it allows only output of dencrypted file"
  echo -e "                               Any exit value except 0 can be considered an error. Overrides --verbose!"
  echo -e "                               ${BOLD}not mandatory${NORM}"
  echo -e "    ${BOLD}--verbose${NORM}    <NONE>      --be more verbose by printing INFO messages"
  echo -e "                               Has no effect if --quiet is set"
  echo -e "                               ${BOLD}not mandatory${NORM}"
 else
  case "$ACTION" in
   'enc')
    echo -e "${REV}WARNING: the enc parameter encrypts FILE and overwrites the unencrypted file with the crypted content${NORM}"
    echo -e "${BOLD}${ACTION}${NORM}            --encrypts a file"
    echo -e "${SCRIPT} ${BOLD}${ACTION}${NORM} -f|--file /path/to/file -p|--pass 'mySecret' [[-c|--cipher] blowfish] [-d|--digest] sha256] [-r|--rounds] 1] [-s|--scrypt]"
   ;;
   'dec')
    echo -e "${BOLD}${ACTION}${NORM}            --decrypts a file to a temp file, display its unencrypted content and deletes the temp file"
    echo -e "                 do NOT use this action on binary files! Makes only sense with text files"
    echo -e "${SCRIPT} ${BOLD}${ACTION}${NORM} -f|--file /path/to/file -p|--pass 'mySecret' [[-c|--cipher] blowfish] [-d|--digest] sha256] [-r|--rounds] 1] [-s|--scrypt] [--force]"
   ;;
   'dec-write')
    echo -e "${BOLD}${ACTION}${NORM}      --decrypts a file and copy the unencrypted file back to its origin in the filesystem"
    echo -e "                 use only this decryption action when handling binary files"
    echo -e "${SCRIPT} ${BOLD}${ACTION}${NORM} -f|--file /path/to/file -p|--pass 'mySecret' [[-c|--cipher] blowfish] [-d|--digest] sha256] [-r|--rounds] 1] [-s|--scrypt] [--force]"
   ;;
   'dec-disp')
    echo -e "${BOLD}${ACTION}${NORM}       --decrypts a file to a temp file, display its unencrypted content and deletes the temp file"
    echo -e "                 do NOT use this action on binary files! Makes only sense with text files"
    echo -e "${SCRIPT} ${BOLD}${ACTION}${NORM} -f|--file /path/to/file -p|--pass 'mySecret' [[-c|--cipher] blowfish] [-d|--digest] sha256] [-r|--rounds] 1] [-s|--scrypt] [--force]"
   ;;
  esac
 fi
 exit 0
}


#Define vars for commandline args
#only change from here on if you know what you do :-)
ACTION=''
FILE=''
CIPHER=''
KEY=''
FORCE=0
SCRYPT=0
KEYSIZE=448
[ "x$*" = 'x' ] && $0 --help
# Generate file with cipher types supported by openssl
# echo "$(openssl enc -h 2>&1 | grep 'Cipher Types' -A 100 | grep '-')" >$TMP_DIR/ciphers.txt
#cat /tmp/ciphers.txt && exit 0
 
#Read args from cli
while (( $# )) ; do
 case "$1" in
  'dec-write' | 'enc' | 'dec-disp' | 'dec' )
   ACTION="$1"
   shift
  ;;
  '-f' | '--file')
   shift
   FILE="$1"
   shift
  ;;
  '-d' | '--digest')
   shift
   DIGEST="$1"
   shift
  ;;
  '-c' | '--cipher')
   shift
   CIPHER="$1"
   shift
  ;;
  '-p' | '--pass')
   shift
   KEY="$1"
   shift
  ;;
  '-s' | '--scrypt')
   shift
   SCRYPT="$1"
   shift
  ;;
  '--quiet')
   shift
   QUIET=$1
   shift
  ;;
  '-k' | '--keysize')
   shift
   KEYSIZE=$1
   shift 
  ;;
  '-v' | '--verbose')
   VERBOSE=1
   shift
  ;;
  '-r' | '--rounds')
   shift
   ROUNDS=$1
   shift
  ;;
  '--salt')
   shift
   SALT=$1
   shift
  ;;
  '-sc' | '--show-ciphers')
   do_showParams 'cipher'
   echo "${BOLD}Supported cipher types (alias)${NORM}"
   printf "$AliasCipherString" | column -t
   echo "${BOLD}Supported cipher types (non-alias)${NORM}"
   printf "$CipherString" | column -t
   echo ""
   echo -e "${REV}This lists supported ciphers by openssl. That not necessarly mean they can/should be used by ${SCRIPT}!!${NORM}"
   echo "Cipher types above can be specified as -c or --cipher to $(basename $0)"
   echo "Leave out leading - when using as argument"
   echo -e "\"safe\" values for ${SCRIPT}: ${BOLD}aesXXX aes-XXX-cbc blowfish bf-cbc cameliaXXX camelia-XXX-cbc${NORM}"  
   echo -e "other ciphers might work or may not. Tested only with ciphers above. Especially ciphers with gcm wont work!!"
   exit 0
  ;;
  '-sd' | '--show-digests')
   do_showParams 'digest'
   echo "${BOLD}Supported digest types (aliases)${NORM}"
   printf "$AliasDigestString" | column -t
   echo "${BOLD}Supported digest types (non-alias)${NORM}"
   printf "$DigestString" | column -t
   echo ""
   echo -e "${REV}This lists supported digests by openssl. That not necessarly mean they can/should be used by ${SCRIPT}!!${NORM}"
   echo -e "\"safe\" values for ${SCRIPT}: ${BOLD}md5 sha sha1 ripmed160 sha224 sha256 sha384 sha512 whirlpool${NORM}"
   echo -e "other ciphers might work or may not. Tested only with digests above."
   echo -e "Although md5, sha and sha1 are supported ${BOLD}I strongly recommend to NOT use them${NORM} as they are considered weak."
   echo -e "One should use a ${BOLD}hash length of at least 160 bits${NORM} to be more or less secure from useful collisions!!"
   echo ""
   exit 0
  ;;
  '--force')
   FORCE=1
   shift
  ;;
  '-h' | '--help')
   do_showHelp
  ;;
  '-v' | '--version')
   echo "${SCRIPT} version $VERSION by <tobster@brain-force.ch>"
   exit 0
  ;;
  *)
   echo "Unknown paramter $1"
   do_showHelp
  ;; 
 esac
done

# enforce disable scrypt as it's not working so far

#echo $QUIET
#exit

#Checks for args given by user
[ -z "$FILE" ] && do_printMessage 'FATAL' 'No FILE given' 1
[[ "x$FILE" != x  && ! -f "$FILE" ]] && do_printMessage 'FATAL' "Given FILE not found. Check $FILE" 1
[ -z "$ACTION" ] && do_printMessage 'FATAL' 'No ACTION given' 1
[ -z "$CIPHER" ] && do_printMessage 'INFO' 'No CIPHER given <blowfish> will be used' -1 && CIPHER='blowfish'
#[[ "$CIPHER" != 'blowfish' && -z "$(cat $TMP_DIR/ciphers.txt | grep -i '\-'${CIPHER}' ')" ]] && CIPHER='blowfish' && do_printMessage 'INFO' "$CIPHER not found. <blowfish> will be used" -1
[ -z "$DIGEST" ] && DIGEST='sha256' && do_printMessage 'INFO' 'No digest given. <sha256> will be used instead' -1
if [ -n "$DIGEST" ] ; then
 case $DIGEST in
  md|md5|sha1|sha224|sha256|sha384|sha512|md4|whirlpool|ripemd160)
 ;;
 *)
  DIGEST='sha256' && do_printMessage 'INFO' 'No or a non-valid DIGEST given <sha256> will be used' -1
 ;;
 esac
fi

if [[ "x$KEY" != 'x' && -e "$KEY" && -f "$KEY" ]] ; then
  KEY=$(head -n 1 $KEY)
fi
if [ "x$KEY" = 'x' ] ; then
  DATE="$(date +'%b %d %H:%M:%S.%3N') $(hostname) $(basename $0)[$$]: ($(whoami)):"
  echo -n "${DATE} INFO: provide a password: "
  while read line ; do
    [ "x$(echo $line)" = 'x' ] && continue
    pass="$line"
    break
  done </dev/stdin 
  echo -n "${DATE} INFO: confirm a password: "
  while read line ; do
    [ "x$(echo $line)" = 'x' ] && continue
    verify="$line"
    break
  done </dev/stdin
  if [ "$verify" != "$pass" ] ; then
    do_printMessage 'FATAL' 'both passwords not equal' 1  
  else
    KEY="$pass"
  fi
fi

if [ $ROUNDS -eq 0 ] ; then
 do_printMessage 'WARN' 'No additional password hashing is performed. Using plain password as encryption key' -1
 do_printMessage 'WARN' 'do you really want to proceed?' -1 
 do_printMessage 'WARN' 'anything not being [YES] case insensitive will be considered as no which is the default: ' -1
 while read line ; do 
  [ "x$(echo $line)" = 'x' ] && continue 
  [ "x$(echo $line|egrep '^[yY][eE][sS]$')" = 'x' ] && do_printMessage 'FATAL' "exit as no hashing of password is used (ROUNDS=$ROUNDS) and no user confirmation received" 1 
  break 
 done </dev/stdin
 do_printMessage 'OK' 'proceed with no hashing of the encryption password as user confirmation received' -1
fi 
KEYFILE="${TMP_DIR}/"
KEYFILE="${KEYFILE}$(python $DIR/helper/randomFilename.py)"

echo "$KEY" > $KEYFILE

case $ACTION in
 'enc')
  python ./crypt.py -p $KEYFILE -f $FILE -c $CIPHER -d $DIGEST -r $ROUNDS -s $SCRYPT -k $KEYSIZE enc
  ret=$?
  rm $KEYFILE >/dev/null 2>&1
  [ $ret -ne 0 ] && ret=2
  exit $ret
 ;;
 'dec-disp' | 'dec')
  python ./crypt.py -p $KEYFILE -f $FILE -c $CIPHER -d $DIGEST -r $ROUNDS -s $SCRYPT -k $KEYSIZE dec
  ret=$?
  rm $KEYFILE >/dev/null 2>&1
  [ $ret -ne 0 ] && ret=3
  exit $ret
 ;;
 'dec-write')
  python ./crypt.py -p $KEYFILE -f $FILE -c $CIPHER -d $DIGEST -r $ROUNDS -s $SCRYPT -k $KEYSIZE dec-write
  ret=$?
  rm $KEYFILE >/dev/null 2>&1
  [ $ret -ne 0 ] && ret=4
  exit $ret
 ;;
esac
