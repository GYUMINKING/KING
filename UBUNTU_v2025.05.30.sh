#!/bin/sh

LANG=C
export LANG
BUILD_VER=1.0
LAST_UPDATE=2021.03
alias ls=ls
_HOST_NAME=`hostname`
DATE=`date '+%F'`dldlrmf
CREATE_FILE=`hostname`"_before_ini_".txt

echo "=============================================================================="
echo "		Ubuntu Vulnerability Scanner Version $BUILD_VER ($LAST_UPDATE)"
echo " 		   Copyright 2021 fou SECURITY. All rights reserved."
echo "=============================================================================="
echo " "
echo " "
echo "========= Starting Ubuntu Vulnerability Scanner $BUILD_VER ========="
echo " "
echo " "
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo "		Ubuntu Vulnerability Scanner Version $BUILD_VER ($LAST_UPDATE)"			  >> $CREATE_FILE 2>&1
echo " 		   Copyright 2021 fou SECURITY. All rights reserved." 				  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "========= Starting Ubuntu Vulnerability Scanner $BUILD_VER ========="			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo "Check Time : `date`"                                                            >> $CREATE_FILE 2>&1
echo "Hostname   : `hostname`"														  >> $CREATE_FILE 2>&1
echo "Kernal     : `uname -a`"														  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo "[Apache 활성화 여부]" >> $CREATE_FILE 2>&1
#Apache 환경설정 관련
web='default'
path='none'
if [ `ps -ef | egrep -i "httpd|apache2" | grep -v "grep" | grep -v "ns-httpd" | grep -i -v "IBM" | grep -i -v "ihs" | grep -i -v "ohs" | wc -l` -ge 1 ]; then 	
	if [ `ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | grep -i -v "IBM" | grep -i -v "ihs" | grep -i -v "ohs" | awk -F' ' '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -ge 1 ]; then
		web='httpd'
		ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | awk -F' ' '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq >> webdir.txt
		webdir=`cat -n webdir.txt | grep 1 | awk -F' ' '{print $2}'`
		
		($webdir -V >pathinfo.txt ) 2>error.txt
		
		if [ -s pathinfo.txt ]; then
			apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
			conf=`$webdir -V | grep -i "server_config_file" | awk -F'"' '{print $2}'`
			if [ ! -f $conf ];then
				path='ok'
				conf="$apache/$conf"
				docroot=`cat "$conf" |grep DocumentRoot |grep -v '\#'|awk -F'"' '{print $2}'`
				svrroot=`cat "$conf" |grep ServerRoot |grep -v '\#'|awk -F'"' '{print $2}'`
				svrroot=${svrroot:-"$apache"}
			fi
			#docroot=`cat $conf | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
		fi
		rm -rf webdir.txt
		$webdir -v >> $CREATE_FILE 2>&1
	elif [ `ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | grep -i -v "IBM" | grep -i -v "ihs" | grep -i -v "ohs" | awk -F' ' '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -ge 1 ]; then
		web='httpd'
		ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | grep -i -v "IBM" | grep -i -v "ohs" | awk -F' ' '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq >> webdir.txt
		webdir=`cat -n webdir.txt | grep 1 | awk -F' ' '{print $2}'`
		
		
		($webdir -V >pathinfo.txt ) 2>error.txt
		
		if [ -s pathinfo.txt ]; then
			apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
			conf=`$webdir -V | grep -i "server_config_file" | awk -F'"' '{print $2}'`
			echo $conf
			if [ ! -f $conf ];then
				path='ok'
				conf="$apache/$conf"
				echo $conf
				docroot=`cat "$conf" |grep DocumentRoot |grep -v '\#'|awk -F'"' '{print $2}'`
				svrroot=`cat "$conf" |grep ServerRoot |grep -v '\#'|awk -F'"' '{print $2}'`
				svrroot=${svrroot:-"$apache"}
			fi
			#docroot=`cat $conf | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
		fi
		#docroot=`cat $conf | grep -i documentroot | grep -v '#' | awk -F'"' '{print $2}'`
		rm -rf webdir.txt
		$webdir -v >> $CREATE_FILE 2>&1
	else
		echo "Apache 환경 변수 세팅 미흡. 수동점검 필요" >> $CREATE_FILE 2>&1
	fi	
else
	echo "Apache 서비스 비활성화" >> $CREATE_FILE 2>&1
fi
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1

U_01() {
	echo "[U-01] root 계정 원격 접속 제한"
	echo "[U-01] root 계정 원격 접속 제한" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START]"  >> $CREATE_FILE 2>&1
	echo "TELNET 판단기준 : TELNET을 사용하지 않거나 Root 직접 접속 차단 설정" >> $CREATE_FILE 2>&1
	
	echo "판단기준 참고 : auth required pam_securetty.so (pam_faillock.so) 설정 및 pts/x 미설정시 양호" >> $CREATE_FILE 2>&1
	echo "1. 현황 : Telnet 서비스 구동 확인" >> $CREATE_FILE 2>&1
	echo "1-1. ps -ef | grep 'telnet'" >> $CREATE_FILE 2>&1			
	ps -ef | grep 'telnet' | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "1-2 netstat -na | grep -i ":23 "" >> $CREATE_FILE 2>&1	
	netstat -na | grep -i ":23 " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1 
	echo "2. 현황 : /etc/pam.d/login 상세 내용" >> $CREATE_FILE 2>&1
	cat /etc/pam.d/login >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "3. 현황 : /etc/securetty 상세 내용"  >> $CREATE_FILE 2>&1
	cat /etc/securetty >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1
	echo "판단기준 : 원격 터미널 서비스를 사용하지 않거나, SSH의 설정 파일 중 PermitRootLogin값을 No로 설정시 양호" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "1. 서비스 현황" >> $CREATE_FILE 2>&1
	ps -ef | grep 'ssh' | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "[START CONFIG]" >> $CREATE_FILE 2>&1
	ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
	for file in $ServiceDIR 
	do
	    echo " " >> $CREATE_FILE 2>&1
	    echo "2. 현황 : $file 설정 파일 (결과 없을시 PermitRootLogin 미설정)" >> $CREATE_FILE 2>&1
	    cat $file | grep PermitRootLogin | grep -v '^#' >> $CREATE_FILE 2>&1
		# grep -vq > grep -v
		if cat $file | grep PermitRootLogin | grep -v '^#'; then
			#if [[ "$COMMAND" =~ "yes" || -z $COMMAND ]]; then
			#24.08.05 수정 
			if [ `cat $file | grep PermitRootLogin | grep -v "^#" | awk '{print $2}'` = "yes" ]; then
				RESULT="N"
			elif [ `cat $file | grep PermitRootLogin | grep -v "^#" | awk '{print $2}'` = "no" ]; then
				RESULT="Y"
			else
				RESULT="판단결과 : 수동"
			fi
		fi
	done

	echo "[END CONFIG]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[START RESULT]" >> $CREATE_FILE 2>&1
	echo $RESULT >> $CREATE_FILE 2>&1
	echo "[END RESULT]" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "[U-01] END " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
echo "=============================================== " >> $CREATE_FILE 2>&1




	echo "② SSH 프로세스 데몬 동작 확인 " >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

	if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SSH 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
		result_sshd='true'

	else
		ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1 
		echo "☞ SSH 서비스 활성화되어 있습니다." >> $CREATE_FILE 2>&1

		echo " " >> $CREATE_FILE 2>&1 
		echo " " >> $CREATE_FILE 2>&1 

		echo "③ sshd_config파일 확인" >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

		echo " " > ssh-result.fou

		ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/opt/ssh/sshd_config"

		for file in $ServiceDIR
		do
			if [ -f $file ]
			then
				if [ `cat $file | grep "PermitRootLogin" | grep -v "setting" | wc -l` -gt 0 ]
				then
					cat $file | grep "PermitRootLogin" | grep -v "setting" | awk '{print "SSH 설정파일('${file}'): "}' >> ssh-result.fou
					echo " " >> $CREATE_FILE 2>&1
					cat $file | grep "PermitRootLogin" | grep -v "setting" | awk '{print $0 }' >> ssh-result.fou 

					if [ `cat $file | egrep -i "PermitRootLogin no|PermitRootLogin prohibit-password" | grep -v '^#' | wc -l` -gt 0 ]
						then
							result_sshd='true'
						else
							result_sshd='false'
					fi
					
				else	
					echo "☞ SSH 설정파일($file): PermitRootLogin 설정이 존재하지 않습니다." >> ssh-result.fou
				fi
				
				if [ `cat $file | grep -i "banner" | grep -v "default banner" | wc -l` -gt 0 ]
				then
					cat $file | grep -i "banner" | grep -v "default banner" | awk '{print "SSH 설정파일('${file}'): " $0 }' >> ssh-banner.fou
				else
					echo "☞ ssh 로그인 전 출력되는 배너지정이 되어 있지 않습니다. " >> ssh-banner.fou
				fi	
			fi
		done 
			
		if [ `cat ssh-result.fou | grep -v "^ *$" | wc -l` -gt 0 ]
		then
			cat ssh-result.fou | grep -v "^ *$" >> $CREATE_FILE 2>&1
		else
			echo "☞ SSH 설정파일을 찾을 수 없습니다. (인터뷰/수동점검)" >> $CREATE_FILE 2>&1
		fi
	fi

	echo " " >> $CREATE_FILE 2>&1 
	echo " " >> $CREATE_FILE 2>&1 
  
	if [ $result_telnet='true' -a $result_pam_telnet='true' -a $result_sshd='true' ]
	then
		echo "★ U-01. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-01. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf ssh-result.fou 

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_02() {
	echo -n "U-02. 패스워드 복잡성 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-02. 패스워드 복잡성 설정" >> $CREATE_FILE 2>&1
	echo ":: 영문·숫자·특수문자가 혼합된 9자리 이상의 패스워드가 설정된 경우 양호"        >> $CREATE_FILE 2>&1
	echo "minlen : 패스워드 최소길이, dcredit : 숫자, ucredit:대문자, lcredit: 소문자, ocredit: 특수문자 " >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "-----------------------[참고]------------------------" >> $CREATE_FILE 2>&1
	echo "minalpha = 2 (비밀번호에 포함될 최소 알파벳 수)" >> $CREATE_FILE 2>&1
	echo "mindiff = 2 (새로운 암호에서 이전 암호에 없는 문자 수)" >> $CREATE_FILE 2>&1
	echo "minother = 2 (알파벳이 아닌 문자 최소 개수)" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	
	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1 
	echo " " >> $CREATE_FILE 2>&1

	echo "" > U-02.fou 2>&1
	
	echo "① 패스워드 복잡도 설정 확인 : /etc/pam.d/common-auth " >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat /etc/pam.d/common-auth | egrep -i "minlen|dcredit|ucredit|lcredit|ocredit" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	
	if [ -f /etc/pam.d/common-auth ]
	then
		OPTIONS="lcredit ucredit dcredit ocredit"
		
		for option in $OPTIONS
		do
			if [ `cat /etc/pam.d/common-auth | grep -v "#" | grep -i $option | wc -l` -eq 1 ]
			then
				if [ `cat /etc/pam.d/common-auth | grep -v "#" | grep -i $option | awk -F "$option=" '{print $2}' | cut -d ' ' -f1` -ne 0 ]
				then
					echo "GOOD" >> U-02.fou 2>&1 
				fi
			fi
		done

	else
		echo "☞ /etc/pam.d/common-auth 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "BAD" >> U-02.fou 2>&1
	fi

	if [ `cat U-02.fou | grep "GOOD" | wc -l` -ge 3 ]
	then
		echo "★ U-02. 결과 : 양호" >> $CREATE_FILE 2>&1
	
	else
		echo "★ U-02. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi
	
	rm -rf U-02.fou
	
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_03() {
	echo -n "U-03. 계정 잠금 임계값 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-03. 계정 잠금 임계값 설정" >> $CREATE_FILE 2>&1
	echo ":: 계정 잠금 임계값이 5이하의 값으로 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1 
	echo " " >> $CREATE_FILE 2>&1

		if [ `cat /etc/pam.d/common-auth | egrep "pam_tally.so|pam_tally2.so" | grep -v "^#" | wc -l` -gt 0 ]
		 then
			cat /etc/pam.d/common-auth | egrep "pam_tally.so|pam_tally2.so" | grep -v "^#" >> $CREATE_FILE 2>&1
		 else 
		 	if [ `cat /etc/pam.d/common-auth | grep "pam_faillock.so" | grep -v "^#" | wc -l` -gt 0 ]
		      then
			    cat /etc/pam.d/common-auth | grep "pam_faillock.so" | grep -v "^#" >> $CREATE_FILE 2>&1
		      else
			    echo "☞ /etc/pam.d/common-auth 파일에 설정값이 없습니다." >> $CREATE_FILE 2>&1
		    fi	 	
		fi
		
		echo " " >> $CREATE_FILE 2>&1
		
		if [ `cat /etc/pam.d/common-auth | grep -v '^#' | egrep "pam_tally.so|pam_tally2.so|pam_faillock.so" | wc -l` -gt 0 ]
		then
			if [ `cat /etc/pam.d/common-auth | grep -v '^#' | egrep "deny=[1-5]" | wc -l` -gt 0 ]
			then  
				echo "★ U-03. 결과 : 양호" >> $CREATE_FILE 2>&1
			else
				echo "★ U-03. 결과 : 취약" >> $CREATE_FILE 2>&1
			fi
		else
			echo "★ U-03. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_04() {
	echo -n "U-04. 패스워드 파일 보호 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-04 패스워드 파일 보호" >> $CREATE_FILE 2>&1
	echo ":: 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우 양호" >> $CREATE_FILE 2>&1
	echo " PS: 정상, NP: 패스워드 없음 , LK:Lock 상태거나 NP 상태 " >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	cat /etc/passwd | grep -v "\*" | grep -v nologin | grep -v false | awk -F: '{print $1}' > PW.txt

	for P in `cat PW.txt`
	do
		passwd -S $P >> sd.txt
	done

	for W in `cat PW.txt`
	do
		cat /etc/shadow | grep -v '*' |grep -w $W >> d2.txt
	done

	echo "☞ 활성화 계정 /etc/shadow 패스워드 현황" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat d2.txt >> $CREATE_FILE 2>&1

	echo "" >> $CREATE_FILE 2>&1
	echo "☞ 활성화 계정 패스워드 상태" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat sd.txt >> $CREATE_FILE 2>&1

	echo "" >> $CREATE_FILE 2>&1

	if [ `awk -F" " '{print $2}' sd.txt | grep -i "np" | wc -l` -eq 0 ]
	then
		echo "★ U-04. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-04. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf PW.txt sd.txt d2.txt

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_44() {
	echo -n "U-44. root 이외의 UID '0' 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-44. root 이외의 UID '0' 금지" >> $CREATE_FILE 2>&1
	echo ":: root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "① UID가 0인 계정 확인 " >> $CREATE_FILE 2>&1 
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/passwd ]
	then
		awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/passwd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1 
	fi

	echo " " >> $CREATE_FILE 2>&1

	echo "② /etc/passwd 파일 내용" >> $CREATE_FILE 2>&1
	cat /etc/passwd >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ `awk -F: '$3==0  { print $1 }' /etc/passwd | grep -v "root" | wc -l` -eq 0 ]
	then
		echo "★ U-44. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-44. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_45() {
	echo -n "U-45. root계정 su 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-45. root계정 su 제한" >> $CREATE_FILE 2>&1
	echo ":: su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/pam.d/su ]
	then
		echo "① /etc/pam.d/su 파일" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/pam.d/su 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	echo "② /bin/su 파일" >> $CREATE_FILE 2>&1
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /bin/su ]
	then
	  ls -al /bin/su >> $CREATE_FILE 2>&1
	else
	  echo "☞ /bin/su 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	
	echo " " >> $CREATE_FILE 2>&1

	echo "③ /usr/bin/su 파일" >> $CREATE_FILE 2>&1
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /usr/bin/su ]
	then
	  ls -al /usr/bin/su >> $CREATE_FILE 2>&1
	else
	  echo "☞ /usr/bin/su 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1	
	fi

	echo " " >> $CREATE_FILE 2>&1

	echo "④ /etc/group 파일" >> $CREATE_FILE 2>&1
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
	cat /etc/group >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1

	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v '^#' | grep -v 'trust' | wc -l` -ge 1 ]
	then
		if [ -f /bin/su ]
		then
			if [ `ls -alL /bin/su | grep ".....-.---" | wc -l` -eq 1 ]
			then
				if [ `ls -alL /bin/su | awk '{print $4}' | grep "root" | wc -l` -eq 0 ]
				then
					echo "★ U-45. 결과 : 양호" >> $CREATE_FILE 2>&1
				else
					echo "★ U-45. 결과 : 취약" >> $CREATE_FILE 2>&1
				fi	
			else
				echo "★ U-45. 결과 : 취약" >> $CREATE_FILE 2>&1
			fi
		else
			echo "★ U-45. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi
	else
		echo "★ U-45. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_46() {
	echo -n "U-46. 패스워드 최소 길이 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-46. 패스워드 최소 길이 설정" >> $CREATE_FILE 2>&1
	echo ":: 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우"  >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/login.defs ]
	then
		echo "① 패스워드 설정 현황" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "^#" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo " " > password.fou

	if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "^#" | awk '{print $2}'` -ge 9 ]
    then
		echo "GOOD" >> password.fou 2>&1
	else
		echo "BAD" >> password.fou 2>&1
	fi

	if [ `cat password.fou | grep "BAD" | wc -l` -eq 0 ]
	then
		echo "★ U-46. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-46. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf password.fou

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_47() {
	echo -n "U-47. 패스워드 최대 사용기간 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-47. 패스워드 최대 사용기간 설정" >> $CREATE_FILE 2>&1
	echo ":: 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/login.defs ]
	then
		echo "① 패스워드 설정 현황" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "^#" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
	fi

	#170131
	echo " " >> $CREATE_FILE 2>&1
	echo " " > password.fou
	pass_max_days=`cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "^#" | awk '{print $2}'`

	if [ $pass_max_days -gt 0 ] && [ $pass_max_days -le 90 ]
	then
		echo "GOOD" >> password.fou 2>&1	
	else
		echo "BAD" >> password.fou 2>&1
	fi


	if [ `cat password.fou | grep "BAD" | wc -l` -eq 0 ]
	then
		echo "★ U-47. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-47. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf password.fou

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_48() {
	echo -n "U-48. 패스워드 최소 사용기간 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-48. 패스워드 최소 사용기간 설정" >> $CREATE_FILE 2>&1
	echo ":: 패스워드 최소 사용기간이 1일(1주)로 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/login.defs ]
	then
		echo "① 패스워드 설정 현황" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "^#" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	echo " " > password.fou

	if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "^#" | awk '{print $2}'` -ge 1 ]
	then
		echo "GOOD" >> password.fou 2>&1
	else
		echo "BAD" >> password.fou 2>&1
	fi

	if [ `cat password.fou | grep "BAD" | wc -l` -eq 0 ]
	then
		echo "★ U-48. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-48. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf password.fou


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_49() {
	echo -n "U-49. 불필요한 계정 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-49. 불필요한 계정 제거" >> $CREATE_FILE 2>&1
	echo ":: 불필요한 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "① 기본 시스템 계정(adm, sync, shutdown, halt, news, operator, games, gopher, nfsnobody, squid, guest) " >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

	if [ `cat /etc/passwd | egrep -v "false|nologin" | egrep "^adm:|^sync:|^shutdown:|^halt:|^news:|^operator:|^games:|^gopher:|^nfsnobody:|^squid:|^guest:"| wc -l` -eq 0 ]
	then
		echo "☞ 불필요한 기본 시스템 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "good" >> fousec_id.txt 2>&1 
	else
		cat /etc/passwd  | egrep -v "false|nologin" | egrep "^adm:|^sync:|^shutdown:|^halt:|^news:|^operator:|^games:|^gopher:|^nfsnobody:|^squid:|^guest:" >> $CREATE_FILE 2>&1
		echo "bad" >> fousec_id.txt 2>&1 
	fi
	
	echo " " >> $CREATE_FILE 2>&1

	echo "② 서버계정 리스트 " >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat /etc/passwd | egrep -v "false|nologin" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "③ 계정 접속 로그(lastlog) " >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	lastlog >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1

	if [ `cat fousec_id.txt | grep "bad" | wc -l` -eq 0 ]
	then
		echo "★ U-49. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-49. 결과 : 수동점검" >> $CREATE_FILE 2>&1
	fi
	
	rm -rf fousec_id.txt

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_50() {
	echo -n "U-50. 관리자 그룹에 최소한의 계정 포함 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-50. 관리자 그룹에 최소한의 계정 포함" >> $CREATE_FILE 2>&1
	echo ":: 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/group ]
	then
		echo "① 관리자 그룹 계정 현황 " >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		cat /etc/group | grep "root:" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/group 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	cat /etc/group | grep "root:" | awk -F: '$4!=null { print $4 }' > group.txt 2>&1

	if [ `cat group.txt | wc -l` -ne 0 ]
	then
		if [ `cat group.txt | awk -F, '{for (i=1;i<=NF;i++) {if($i!="root") print $i}}' | wc -l ` -eq 0 ]
		then
			echo "★ U-50. 결과 : 양호" >> $CREATE_FILE 2>&1
		else
			echo "★ U-50. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi
	else
		echo "★ U-50. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi

	rm -rf group.txt

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_51() {
	echo -n "U-51. 계정이 존재하지 않는 GID 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-51. 계정이 존재하지 않는 GID 금지" >> $CREATE_FILE 2>&1
	echo ":: 구성원이 없거나, 더 이상 사용하지 않는 그룹을 삭제한 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	
	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
    
	echo "① /etc/group 파일 내역" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat /etc/group >> $CREATE_FILE 2>&1
	
	echo " " >> $CREATE_FILE 2>&1
	echo "② /etc/passwd 파일 내역" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	cat /etc/passwd >> $CREATE_FILE 2>&1
	
	echo " " >> $CREATE_FILE 2>&1
	
	echo "③ 구성원이 존재하지 않는 그룹" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	awk -F: '$4==null' /etc/group | awk -F":" '$3 >= 500' | grep -v "^#" > no_4.txt
	awk -F: '{print $3}' no_4.txt > gid_group.txt 
	echo " " >> $CREATE_FILE 2>&1
	
	if [ -f gid_group.txt ] 
	 then 
	     for D in `cat gid_group.txt` 
	     do 
		   awk -F: '{print $4}' /etc/passwd | grep -w $D > gid_1.txt 

		if [ `cat gid_1.txt | wc -l` -gt 0 ]
		then 
			echo "gid=$D"  > /dev/null 
		else 
			echo $D >> gid_none.txt 
		fi 
	done
	fi
	
	if [ -f gid_none.txt ]
	  then
	    if [ `cat gid_none.txt | wc -l` -gt 0 ]
	      then
		    for A in `cat gid_none.txt` 
		    do
			awk -F: '{print $1, $3}' /etc/group | grep -w $A >> $CREATE_FILE 2>&1  
		    done 
         	echo " " >> $CREATE_FILE 2>&1
		    echo "★ U-51. 결과 : 취약" >> $CREATE_FILE 2>&1 
	      else
		echo " " >> $CREATE_FILE 2>&1
		echo "★ U-51. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi
	else
		echo "★ U-51. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi
	
	rm -rf no_4.txt
	rm -rf gid_group.txt 
	rm -rf gid_none.txt 
	rm -rf gid_1.txt   

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_52() {
	echo -n "U-52. 동일한 UID 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-52. 동일한 UID 금지" >> $CREATE_FILE 2>&1
	echo ":: 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	
	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	
	for uid in `cat /etc/passwd | awk -F: '{print $3}'`
	do
		cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }' > account.fou
	    if [ `cat account.fou | wc -l` -ge 2 ]
		then
			cat account.fou >> total-account.fou
		fi
	done

	echo "① 동일 UID 계정 확인" >> $CREATE_FILE 2>&1
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1	
	if [ -f total-account.fou ]
     then 	
	  if [ `sort -k 1 total-account.fou | wc -l` -gt 1 ]
	   then
		sort -k 1 total-account.fou | uniq -d >> $CREATE_FILE 2>&1
	   else
		echo "☞ 동일한 UID를 사용하는 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
	  fi
	  else 
	  echo "☞ 동일한 UID를 사용하는 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	if [ -f total-account.fou ] 
	  then
	    if [ `sort -k 1 total-account.fou | wc -l` -gt 1 ]
	     then
		  echo "★ U-52. 결과 : 취약" >> $CREATE_FILE 2>&1
	     else
		  echo "★ U-52. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi 
		else
      echo "★ U-52. 결과 : 양호" >> $CREATE_FILE 2>&1		
	fi

	rm -rf account.fou
	rm -rf total-account.fou


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_53() {
	echo -n "U-53. 사용자 shell 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-53. 사용자 shell 점검" >> $CREATE_FILE 2>&1
	echo ":: 로그인이 필요하지 않은 계정에 /bin/false(nologin) 쉘이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	
	echo " " >> $CREATE_FILE 2>&1
	
	echo "① shell 부여 현황 확인" >> $CREATE_FILE 2>&1
	echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/passwd ]
	then
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|^guest" | grep -v "admin" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/passwd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher|^guest" |  awk -F: '{print $7}'| egrep -v 'admin|false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
	then
		echo "★ U-53. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-53. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi
	

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_54() {
	echo -n "U-54. Session Timeout 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-54. Session Timeout 설정" >> $CREATE_FILE 2>&1
	echo ":: Session Timeout이 600초(10분) 이하로 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	
	echo " " >> $CREATE_FILE 2>&1
	echo "" > account_sson.fou
	echo "① /etc/profile 파일설정" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1	
	if [ -f /etc/profile ]
	then
		if [ `cat /etc/profile | egrep -i "TMOUT|TIMEOUT" | grep -v "^#" | wc -l` -eq 0 ]
		then
			echo "☞ /etc/profile 파일 내 TMOUT/TIMEOUT 설정이 없습니다." >> $CREATE_FILE 2>&1
			echo "BAD1" >> account_sson.fou
			
		else
			cat /etc/profile | egrep -i "TMOUT|TIMEOUT" >> $CREATE_FILE 2>&1
			if [ `cat /etc/profile | grep -v "^#" | egrep -i "TMOUT|TIMEOUT" | awk -F= '$2<=600' | awk -F= '$2>0' | wc -l` -ge 1 ]
			then
				echo "GOOD" >> account_sson.fou
			else
				echo "BAD1" >> account_sson.fou
			fi
		fi
	else
		echo "☞ /etc/profile 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	if [ -f /etc/csh.login ]
	then
		echo "② /etc/csh.login 파일설정" >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1	

		if [ `cat /etc/csh.login | egrep -i "autologout" | grep -v "^#" | wc -l` -eq 0 ]
		then
			echo "☞ /etc/csh.login 파일 내 autologout 설정이 없습니다." >> $CREATE_FILE 2>&1
			echo "BAD" >> account_sson.fou
			
		else
			cat /etc/csh.login | grep -i "autologout" >> $CREATE_FILE 2>&1

			if [ `cat /etc/csh.login | grep -v "^#" | grep -i 'autologout' | awk -F= '$2<=30' | awk -F= '$2>0' | wc -l` -ge 1  ]
			then
				echo "GOOD" >> account_sson.fou
			else
				echo "BAD" >> account_sson.fou
			fi
		fi

	elif [ -f /etc/csh.cshrc ]
	then
		echo "③ /etc/csh.cshrc 파일설정" >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1	

		if [ `cat /etc/csh.cshrc | egrep -i "autologout" | grep -v "^#" | wc -l` -eq 0 ]
		then
			echo "☞ /etc/csh.cshrc 파일 내 autologout 설정이 없습니다." >> $CREATE_FILE 2>&1
			echo "BAD" >> account_sson.fou
			
		else
			cat /etc/csh.cshrc | grep -i "autologout" >> $CREATE_FILE 2>&1

			if [ `cat /etc/csh.cshrc | grep -v "^#" | grep -i 'autologout' | awk -F= '$2<=30' | awk -F= '$2>0' | wc -l`-ge 1 ]
			then
				echo "GOOD" >> account_sson.fou
			else
				echo "BAD" >> account_sson.fou
			fi
		fi

	else
		echo "☞ /etc/csh.login, /etc/csh.cshrc 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	
	echo " " >> $CREATE_FILE 2>&1

	if [ `cat account_sson.fou | grep "GOOD1" | wc -l` -eq 1 ]
	then
		echo "★ U-54. 결과 : 양호" >> $CREATE_FILE 2>&1    
	else
		echo "★ U-54. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf account_sson.fou

	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_05() {
	echo -n "U-05. root 홈, 패스 디렉터리 권한 및 패스 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-05. root 홈, 패스 디렉터리 권한 및 패스 설정" >> $CREATE_FILE 2>&1
	echo ":: PATH 환경변수에 . 이 맨 앞이나 중간에 포함되지 않은 경우" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1
	echo $PATH >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo " " >> $CREATE_FILE 2>&1

	if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "★ U-05. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-05. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_06() {
	echo -n "U-06. 파일 및 디렉터리 소유자 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-06. 파일 및 디렉터리 소유자 설정" >> $CREATE_FILE 2>&1
	echo ":: 소유자가 존재하지 않은 파일 및 디렉터리가 존재하지 않은 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	echo "① 소유자가 존재하지 않는 파일 (소유자 => 파일위치: 경로)" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	find /tmp \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou 
    find /home \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou 
    find /var \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou 
    find /bin \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou 
    find /sbin \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou 
    find /etc \( -nouser -o -nogroup \) -xdev -ls | awk '{print $5 " => 파일위치:" $11}' >> file-own.fou


	if [ -s file-own.fou ]
	then
		cat file-own.fou >> $CREATE_FILE 2>&1
	else
		echo "☞ 소유자가 존재하지 않는 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	if [ -s file-own.fou ]
	then
		echo "★ U-06. 결과 : 취약" >> $CREATE_FILE 2>&1
	else
		echo "★ U-06. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi

	rm -rf file-own.fou


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_07() {
	echo -n "U-07. /etc/passwd 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-07. /etc/passwd 파일 소유자 및 권한 설정"										>> $CREATE_FILE 2>&1
	echo ":: /etc/passwd 파일의 소유자가 root이고, 권한이 ,644 이하인 경우 양호"			>> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1


	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/passwd ]
	then
		ls -alL /etc/passwd >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/passwd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1


	if [ `ls -alL /etc/passwd | grep "...-.--.--" | wc -l` -eq 1 ]
	then
		echo "★ U-07. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-07. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_08() {
	echo -n "U-08. /etc/shadow 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-08. /etc/shadow 파일 소유자 및 권한 설정"										>> $CREATE_FILE 2>&1
	echo ":: /etc/shadow 파일의 소유자가 root이고, 권한이 400인 경우 양호"				>> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1


	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1


	if [ -f /etc/shadow ]
	then
		ls -alL /etc/shadow >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/shadow 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1


	if [ `ls -alL /etc/shadow | grep "..--------" | wc -l` -eq 1 ]
	then
		echo "★ U-08. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-08. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_09() {
	echo -n "U-09. /etc/hosts 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-09. /etc/hosts 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
	echo ":: /etc/hosts 파일의 소유자가 root이고, 권한이 600인 경우 양호" >> $CREATE_FILE 2>&1  
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	#170201
	if [ -f /etc/hosts ]
	then
		echo "① /etc/hosts 파일 퍼미션" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE
		ls -alL /etc/hosts >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "② /etc/hosts 파일 내용" >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE
		cat /etc/hosts | grep -v "^#" >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/hosts 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1


	if [ `ls -alL /etc/hosts | grep "...-------" | wc -l` -eq 1 ]
	then
		if [ `ls -al /etc/hosts | awk '{print $3}' | grep -i "root" | wc -l` -eq 1 ]
		then
			echo "★ U-09. 결과 : 양호" >> $CREATE_FILE 2>&1
		else
			echo "★ U-09. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi
	else
		echo "★ U-09. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_10() {
	echo -n "U-10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
	echo ":: /etc/(X)inetd.conf파일의 소유자가 root이고, 권한이 600인 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1


	if [ -d /etc/xinetd.d ] 
	then
		echo "① /etc/xinetd.d 디렉터리 내용 현황." >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE
		ls -al /etc/xinetd.d/* >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/xinetd.d 디렉터리가 없습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/xinetd.conf ]
	then
		echo "② /etc/xinetd.conf 파일 퍼미션 현황." >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE
		ls -al /etc/xinetd.conf >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/xinetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	
	echo " " >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
	then
		echo "③ /etc/inetd.conf 파일 퍼미션 현황." >> $CREATE_FILE 2>&1
		echo "-----------------------------------------------" >> $CREATE_FILE
		ls -al /etc/inetd.conf >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	echo " " > inetd.fou

	if [ -f /etc/inetd.conf ]
	then
		if [ `ls -alL /etc/inetd.conf | awk '{print $1}' | grep '...-------'| wc -l` -eq 1 ]
		then
			echo "GOOD" >> inetd.fou
		else
			echo "BAD" >> inetd.fou
		fi
	else
		echo "GOOD" >> inetd.fou
	fi

	if [ -f /etc/xinetd.conf ]
	then
		if [ `ls -alL /etc/xinetd.conf | awk '{print $1}' | grep '...-------'| wc -l` -eq 1 ]
		then
			echo "GOOD" >> inetd.fou
		else
			echo "BAD" >> inetd.fou
		fi
	else
		echo "" >> inetd.fou
	fi
	
	echo " " >> $CREATE_FILE 2>&1
	if [ -d /etc/xinetd.d ]
	then
		if [ `ls -alL /etc/xinetd.d/* | awk '{print $1}' | grep -v '...-------'| wc -l` -gt 0 ]
		then
			echo "BAD" >> inetd.fou
		else
			echo "GOOD" >> inetd.fou
		fi
	else
		echo "GOOD" >> inetd.fou
	fi

	if [ `cat inetd.fou | grep "BAD" | wc -l` -eq 0 ]
	then
		echo "★ U-10. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-10. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi

	rm -rf inetd.fou


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_11() {
	echo -n "U-11. /etc/syslog.conf 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-11. /etc/syslog.conf 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
	echo ":: /etc/syslog.conf 파일의 소유자가 root이고, 권한이 644인 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1


	if [ -f  /etc/rsyslog.conf ]
	then
		echo "☞ rsyslog 파일권한" >> $CREATE_FILE 2>&1
		ls -alL /etc/rsyslog.conf  >> $CREATE_FILE 2>&1
	elif [ -f /etc/syslog.conf ]
	then
		echo "☞ syslog 파일권한" >> $CREATE_FILE 2>&1
		ls -alL /etc/syslog.conf  >> $CREATE_FILE 2>&1
	else 
		echo "☞ syslog-ng 파일권한" >> $CREATE_FILE 2>&1
		ls -alL /etc/syslog-ng.conf  >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1
	if [ -f /etc/syslog.conf ]
	then
		if [ `ls -alL /etc/syslog.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
		then
			echo "GOOD" >> syslog.fou 2>&1
		else
			echo "BAD" >> syslog.fou 2>&1
		fi
	elif [ -f /etc/rsyslog.conf ]
	then 
		if [ `ls -alL /etc/rsyslog.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
		then
			echo "GOOD" >> syslog.fou 2>&1
		else
			echo "BAD" >> syslog.fou 2>&1
		fi
	fi
	
	if [ -f /etc/syslog-ng.conf ]
	then
		if [ `ls -alL /etc/syslog-ng.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
		then
			echo "GOOD" >> syslog.fou 2>&1
		else
			echo "BAD" >> syslog.fou 2>&1
		fi
	fi 

	if [ `cat syslog.fou | grep "BAD" | wc -l` -eq 0 ]
	then
		echo "★ U-11. 결과 : 양호" >> $CREATE_FILE 2>&1
	else
		echo "★ U-11. 결과 : 취약" >> $CREATE_FILE 2>&1
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_12() {
	echo -n "U-12. /etc/service 파일 소유자 및 권한 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-12. /etc/services 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
	echo ":: /etc/services 파일의 소유자가 root이고, 권한이 644인 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	if [ -f  /etc/services ]
	then
		ls -alL /etc/services  >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/services 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
		echo "★ U-12. 결과 : 수동점검" >> $CREATE_FILE 2>&1
	fi

	echo " " >> $CREATE_FILE 2>&1

	if [ -f /etc/services ]
	then
		if [ `ls -alL /etc/services | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
		then
			echo "★ U-12. 결과 : 양호" >> $CREATE_FILE 2>&1
		else
			echo "★ U-12. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi
	fi


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_13() {
	echo -n "U-13. SUID, SGID, Sticky bit 설정파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "==============================================================================" >> $CREATE_FILE 2>&1
	echo "U-13. SUID, SGID, Sticky bit 설정파일 점검 " >> $CREATE_FILE 2>&1
	echo ":: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않을 경우 양호" >> $CREATE_FILE 2>&1
	echo "==============================================================================" >> $CREATE_FILE 2>&1

	echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1

	FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

	for check_file in $FILES
	do
		if [ -f $check_file ]
		then
			if [ -g $check_file -o -u $check_file -o -k $check_file ]
			then
				echo `ls -alL $check_file` >> $CREATE_FILE 2>&1
			else
				echo $check_file "파일에 SUID, SGID, Sticky bit가 부여되어 있지 않습니다." >> $CREATE_FILE 2>&1
			fi
		else
			echo "☞" $check_file "이 없습니다." >> $CREATE_FILE 2>&1
		fi
	done

	echo " " >> $CREATE_FILE 2>&1


	echo " " > set.fou

	FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

	for check_file in $FILES
	do
		if [ -f $check_file ]
		then
			if [ `ls -alL $check_file | awk '{print $1}' | egrep -i 's|t'| wc -l` -gt 0 ]
			then
				ls -alL $check_file |awk '{print $1}' | grep -i 's' >> set.fou
			else
				echo " " >> set.fou
			fi
		fi
	done

	if [ `cat set.fou | awk '{print $1}' | egrep -i 's|t' | wc -l` -ge 1 ]
	then
		echo "★ U-13. 결과 : 취약" >> $CREATE_FILE 2>&1
	else
		echo "★ U-13. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi

	rm -rf set.fou


	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "완료"
	echo " "
}


U_14() {
  echo -n "U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 >>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고," >> $CREATE_FILE 2>&1
  echo "   홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "① 홈 디렉터리 내 환경변수 파일 소유자 및 권한 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
  FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

  for file in $FILES
  do
    FILE=/$file
    if [ -f $FILE ]
      then
        ls -al $FILE >> $CREATE_FILE 2>&1
    fi
  done

  for dir in $HOMEDIRS
  do
    for file in $FILES
    do
      FILE=$dir/$file
        if [ -f $FILE ]
          then
          ls -al $FILE >> $CREATE_FILE 2>&1
        fi
    done
  done
  echo " " >> $CREATE_FILE 2>&1

  echo " " > home.fou

  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "^#"`
  FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

  for file in $FILES
    do
      if [ -f /$file ]
        then
          if [ `ls -alL /$file |  awk '{print $1}' | grep "........-." | wc -l` -eq 0 ]
            then
              echo "BAD" >> home.fou
            else
              echo "GOOD" >> home.fou
          fi
        else
          echo "GOOD" >> home.fou
      fi
    done

  for dir in $HOMEDIRS
    do
      for file in $FILES
        do
          if [ -f $dir/$file ]
            then
              if [ `ls -al $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 0 ]
                then
                  echo "BAD" >> home.fou
                else
                  echo "GOOD" >> home.fou
              fi
            else
              echo "GOOD" >> home.fou
          fi
        done
    done

  if [ `cat home.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-14. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-14. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf home.fou


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_15() {
  echo -n "U-15. world writable 파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-15. world writable 파일 점검 " >> $CREATE_FILE 2>&1
  echo ":: world writable 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고," >> $CREATE_FILE 2>&1
  echo "   world writable 파일에 root와 소유자만 쓰기 권한이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "① world writable 파일 소유자 및 권한 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

  find /tmp -perm -2 -ls | grep -v "srw.rw.rw." | grep -v " lrw.rw.rw." | grep -v "rwt" | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l > world.fou 2>&1
  find /home -perm -2 -ls | grep -v "srw.rw.rw." | grep -v "p.w..w..w." | grep -v " lrw.rw.rw." |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.fou 2>&1
  find /var -perm -2 -ls | grep -v "srw.rw.rw." | grep -v "p.w..w..w." | grep -v " lrw.rw.rw." | grep -v "tmp" | grep -v "dev" | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.fou 2>&1
  find /bin -perm -2 -ls | grep -v "srw.rw.rw."| grep -v "p.w..w..w." | grep -v " lrw.rw.rw."  |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.fou 2>&1 
  find /sbin -perm -2 -ls | grep -v "srw.rw.rw."| grep -v "p.w..w..w." | grep -v " lrw.rw.rw." |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.fou 2>&1

  if [ -s world.fou ]
    then
	  cat world.fou  >> $CREATE_FILE 2>&1
      echo " " >> $CREATE_FILE 2>&1		
	  echo "★ U-15. 결과 : 취약"  >> $CREATE_FILE 2>&1
	
    else
	  echo "☞ World Writable 권한이 부여된 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
      echo "★ U-15. 결과 : 양호"  >> $CREATE_FILE 2>&1
  fi

  rm -rf world.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_16() {
  echo -n "U-16. /dev에 존재하지 않는 device 파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-16. /dev에 존재하지 않는 device 파일 점검 " >> $CREATE_FILE 2>&1
  echo ":: dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 기반시설 점검기준 명령 : find /dev -type f -exec ls -l {} \;" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1 
  find /dev -type f -exec ls -l {} \; > dev-file.fou

  if [ -s dev-file.fou ]
    then
	  cat dev-file.fou >> $CREATE_FILE 2>&1
    else
  	  echo "☞ /dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "② 디바이스 파일(charactor, block file) 점검 : find /dev -type [C B] -exec ls -l {} \;  " >> $CREATE_FILE 2>&1
  echo "major, minor 필드에 값이 올바르지 않은 경우 취약  " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1 
  find /dev -type c -exec ls -l {} \; >> dev-file2.fou
  find /dev -type b -exec ls -l {} \; >> dev-file2.fou
  
  if [ -s dev-file2.fou ]
    then
	  cat dev-file2.fou >> $CREATE_FILE 2>&1
    else
  	  echo "☞ /dev 에 charactor, block Device 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -s dev-file.fou ]
    then
      echo "★ U-16. 결과 : 취약" >> $CREATE_FILE 2>&1
    else
      echo "★ U-16. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  rm -rf dev-file.fou  dev-file2.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_17() {
  echo -n "U-17. $HOME/.rhosts, hosts.equiv 사용 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-17. $HOME/.rhosts, hosts.equiv 사용금지 " >> $CREATE_FILE 2>&1
  echo ":: login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 양호" >> $CREATE_FILE 2>&1
  echo "   1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우" >> $CREATE_FILE 2>&1
  echo "   2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우" >> $CREATE_FILE 2>&1
  echo "   3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 '+' 설정이 없는 경우" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  
  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="rsh|rlogin|rexec|shell|login|exec"

  echo " " >> $CREATE_FILE 2>&1
  echo "① /etc/xinetd.d 서비스 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "☞ r 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "② /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d디렉터리에 r 계열 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="rsh|rlogin|rexec|shell|login|exec"

  echo "③ inetd.conf 파일에서 'r' commnad 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/inetd.conf ]
    then
      cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "r command" > r_temp
              else
                echo "GOOD" >> trust.fou
                result="GOOD"
            fi
          done
        else
          echo "GOOD" >> trust.fou
          result="GOOD"
      fi
    elif [ -f /etc/inetd.conf ]
      then
        if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
          then
            echo "GOOD" >> trust.fou
            result="GOOD"
          else
            echo "r command" > r_temp
        fi
      else
        echo "GOOD" >> trust.fou
        result="GOOD"
  fi


  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
  FILES="/.rhosts"

  

  if [ -s r_temp ]
    then
      if [ -f /etc/hosts.equiv ]
        then
		echo "④ /etc/hosts.equiv 파일 현황 " >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
          ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          echo "■ /etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
          cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/hosts.equiv 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo " " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  

  if [ -s r_temp ]
    then
      for dir in $HOMEDIRS
        do
          for file in $FILES
            do
              if [ -f $dir$file ]
                then
					echo "⑤ $HOME/.rhosts 파일 현황 " >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					ls -alL $dir$file  >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					echo "■ $dir$file 설정 내용" >> $CREATE_FILE 2>&1
					cat $dir$file | grep -v "^#" >> $CREATE_FILE 2>&1
                else
					echo "☞ 설정 내용이 없습니다." >> nothing.fou
              fi
            done
        done
    else
      echo " " >> $CREATE_FILE 2>&1
  fi

  if [ -f nothing.fou ]
    then
      echo "☞ /.rhosts 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  if [ -s r_temp ]
    then
      if [ -f /etc/hosts.equiv ]
        then
          if [ `ls -alL /etc/hosts.equiv |  awk '{print $1}' | grep "....------" | wc -l` -eq 1 ]
            then
              echo "GOOD" >> trust.fou
            else
              echo "BAD" >> trust.fou
          fi
          if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "^#" | wc -l` -eq 0 ]
            then
              echo "GOOD" >> trust.fou
            else
              echo "BAD" >> trust.fou
          fi
        else
          echo "BAD" >> trust.fou
      fi
    else
      echo "GOOD" >> trust.fou
  fi


  if [ -s r_temp ]
    then
      for dir in $HOMEDIRS
	      do
	        for file in $FILES
	          do
	            if [ -f $dir$file ]
	              then
                  if [ `ls -alL $dir$file |  awk '{print $1}' | grep "....------" | wc -l` -eq 1 ]
                    then
                      echo "GOOD" >> trust.fou
                    else
                      echo "BAD" >> trust.fou
                  fi
                  if [ `cat $dir$file | grep "+" | grep -v "grep" | grep -v "^#" |wc -l ` -eq 0 ]
                    then
                      echo "GOOD" >> trust.fou
                    else
                      echo "BAD" >> trust.fou
                  fi
                fi
            done
        done
    else
      echo "GOOD" >> trust.fou
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat trust.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-17. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-17. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi


  rm -rf trust.fou r_temp nothing.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_18() {
  echo -n "U-18. 접속 IP 및 포트 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-18. 접속 IP 및 포트 제한 " >> $CREATE_FILE 2>&1
  echo ":: /etc/hosts.deny 파일에 ALL Deny 설정 후" >> $CREATE_FILE 2>&1
  echo "   /etc/hosts.allow 파일에 접근을 허용할 특정 호스트를 등록한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.deny ]
    then
      if [ `cat /etc/hosts.deny | grep -v "^#" | wc -l` -eq 0 ]
		then
			echo "☞ /etc/hosts.deny 파일 내용이 없습니다.">> $CREATE_FILE 2>&1
		else
			echo "① /etc/hosts.deny 파일 내용" >> $CREATE_FILE 2>&1
			echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
			cat /etc/hosts.deny | grep -v "^#" >> $CREATE_FILE 2>&1
		fi
    else
      echo "☞ /etc/hosts.deny 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.allow ]
    then
      if [ `cat /etc/hosts.allow | grep -v "^#" | wc -l` -eq 0 ]
		then
			echo "☞ /etc/hosts.allow 파일 내용이 없습니다.">> $CREATE_FILE 2>&1
		else
			echo "② /etc/hosts.allow 파일 내용" >> $CREATE_FILE 2>&1
			echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
			cat /etc/hosts.allow | grep -v "^#"  >> $CREATE_FILE 2>&1
		fi
    else
      echo "☞ /etc/hosts.allow 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.deny ]
    then
      if [ `cat /etc/hosts.deny | grep -v "^#" | sed 's/ *//g' | grep "ALL:ALL" | wc -l` -gt 0 ]
        then
          echo "GOOD" > IP_ACL.fou
        else
          echo "BAD" > IP_ACL.fou
      fi
    else
      echo "BAD" > IP_ACL.fou
  fi

  if [ -f /etc/hosts.allow ]
    then
      if [ `cat /etc/hosts.allow | grep -v "^#" | sed 's/ *//g' | grep -v "ALL:ALL" | wc -l` -gt 0 ]
        then
          echo "GOOD" >> IP_ACL.fou
        else
          echo "BAD" >> IP_ACL.fou
      fi
    else
      echo "BAD" >> IP_ACL.fou
  fi  

  if [ `cat IP_ACL.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-29. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-29. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi


rm -rf IP_ACL.fou


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_55() {
  echo -n "U-55. hosts.lpd 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-55. hosts.lpd 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 파일의 소유자가 root이고 Other에 쓰기 권한이 부여되어 있지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f  /etc/hosts.lpd ]
    then
      ls -alL /etc/hosts.lpd  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/hosts.lpd 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.lpd ]
    then
      if [ `ls -alL /etc/hosts.lpd | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
        then
          echo "★ U-55. 결과 : 양호" >> $CREATE_FILE 2>&1
       else
          echo "★ U-55. 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-55. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_56() {
  echo -n "U-56. NIS 서비스 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-56. NIS 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: 불필요한 NIS 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ NIS, NIS+ 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  echo "★ U-56. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  echo "★ U-56. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_57() {
  echo -n "U-57. UMASK 설정 관리 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-57. UMASK 설정 관리 " >> $CREATE_FILE 2>&1
  echo ":: UMASK 값이 022 이하로 설정된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① UMASK 명령어 설정" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  umask  >> $CREATE_FILE 2>&1
  
  if [ `umask | grep "22" | wc -l` -gt 0 ]; then
	echo "GOOD" >> umask.fou	
  else
	echo "BAD" >> umask.fou
  fi

  echo "② /etc/login.defs 파일  " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/login.defs ]
    then
      cat /etc/login.defs | grep -i mask | grep -v "^#" >> $CREATE_FILE 2>&1
      if [ `cat /etc/login.defs | grep -i "umask" | grep -v "^#" | awk -F"0" '$2 < "22"' | wc -l` -gt 0 ]
      then
        echo "BAD" > umask.fou
      else
        echo "GOOD" >> umask.fou
      fi
    else
      echo "☞ /etc/login.defs 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo "  " >> $CREATE_FILE 2>&1
  
  echo "③ /etc/bashrc 파일  " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/bashrc ]
    then
      cat /etc/bashrc | grep -v "^#"| grep -i umask >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/bashrc 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1
  
   echo "④ /etc/csh.cshrc 파일  " >> $CREATE_FILE 2>&1
   echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/csh.cshrc ]
    then
      cat /etc/csh.cshrc | grep -v "^#"| grep -i umask >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/csh.cshrc 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1 
  

 if [ `cat umask.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-57. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-57. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

 rm -rf umask.fou
 
 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_58() {
  echo -n "U-58. 홈 디렉터리 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-58. 홈 디렉터리 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리 소유자가 해당 계정이고, 일반 사용자 쓰기 권한이 제거된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo -n > u58.fou 2>&1
echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
PWDLINE=""
USER=""
USERID=""
USERHOME=""
HOMEID=""
HOMEUSER=""

# 홈디렉터리 소유자 확인
  echo "① 계정/홈 디렉터리/홈 디렉터리 소유자 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

  for PWDLINE in `awk -F":" '{print $1":"$3":"$6":"$7 }'  /etc/passwd | egrep 'sh$' | egrep -v ':nosh'  | sort -u`
	  do
			USER=`echo $PWDLINE | awk -F":" '{print $1}'`
			USERID=`echo $PWDLINE | awk -F":" '{print $2}'`
			USERHOME=`echo $PWDLINE | awk -F":" '{print $3}'`
			if [ -d $USERHOME ]; then
				HOMEID=`ls -nd $USERHOME | awk '{print $3}'`
				HOMEUSER=`ls -ald $USERHOME | awk '{print $3}'`
				if [ -z $HOMEID ]; then
					HOMEID=0
				fi
				if [ $USERID -a $HOMEID ]; then
					if [ $USERID != $HOMEID ]; then
						if [ $USERID -ge 100 ]; then
							echo "$USER : $USERHOME : $HOMEUSER" >> HOMEDIR.txt 2>&1
						fi
					fi
				fi
			fi
	  done
  if [ -s HOMEDIR.txt ]; then
	  echo "■ 계정명과 홈 디렉토리 소유자가 일치하지 않은 계정" >> $CREATE_FILE 2>&1
	  echo "( 계정 : 홈 디렉토리 : 홈 디렉토리 소유자 )" >> $CREATE_FILE 2>&1
	  cat HOMEDIR.txt >> $CREATE_FILE 2>&1
	  echo "BAD" >> u58.fou 2>&1
  else
	  echo "☞ 계정과 홈 디렉토리 소유자가 일치하지 않은 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

# 홈디렉터리 일반사용자 권한 확인
  echo " ② 홈 디렉터리 일반사용자 권한 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  HOMEDIRS2=`cat /etc/passwd | egrep -v "false|nologin"  | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "^#" | grep -v "/tmp" | grep -v "uucppublic" | uniq` 
   
  for dir in $HOMEDIRS2 
    do 
      ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1 
    done 
  echo " " >> $CREATE_FILE 2>&1 
   
  HOMEDIRS2=`cat /etc/passwd | egrep -v "false|nologin" | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "^#" | grep -v "/tmp" | grep -v "uucppublic" | uniq` 
  for dir in $HOMEDIRS2 
    do 
      if [ -d $dir ] 
        then 
          if [ `ls -dal $dir |  awk '{print $1}' | grep "........-." | wc -l` -eq 1 ] 
            then 
              echo "GOOD" >> u58.fou 
            else 
              echo "BAD" >> u58.fou 
          fi 
        else 
          echo "GOOD" >> u58.fou 
      fi 
    done 

    echo " " >> $CREATE_FILE 2>&1

  rm HOMEDIR.txt
  
  echo " " >> $CREATE_FILE 2>&1
  if [ `cat u58.fou | grep -i "BAD" | wc -l ` -ge 1 ]
   then
	  echo "★ U-58. 결과 : 취약" >> $CREATE_FILE 2>&1
  else
	  echo "★ U-58. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  rm -rf u58.fou

  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_59() {
  echo -n "U-59. 홈 디렉터리로 지정한 디렉터리의 존재 관리 >>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-59. 홈 디렉터리로 지정한 디렉터리의 존재 관리 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리가 존재하지 않는 계정이 없고, " >> $CREATE_FILE 2>&1
  echo "   root 계정을 제외한 일반 계정의 홈 디렉터리가 '/'가 아닌 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 홈 디렉터리가 존재하지 않는 계정리스트" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  echo " " > DHOME_pan.fou
  
  HOMEDIRS=`cat /etc/passwd | egrep -v -i "nologin|false" | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "^#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`

  for dir in $HOMEDIRS
    do
	    if [ ! -d $dir ]
	      then
		      awk -F: '$6=="'${dir}'" { print "● 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd >> $CREATE_FILE 2>&1
		      echo " " > Home.fou
		 
	    fi
    done

  echo " " >> $CREATE_FILE 2>&1

  if [ ! -f Home.fou ]
    then
		  echo "☞ 홈 디렉터리가 존재하지 않은 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  echo "② root 계정 외 '/'를 홈디렉터리로 사용하는 계정리스트" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ `cat /etc/passwd | egrep -v -i "nologin|false" | grep -v root | awk -F":" 'length($6) > 0' | awk -F":" '$6 == "/"' | wc -l` -eq 0 ]
  then
        echo "☞ root 계정 외 '/'를 홈 디렉터리로 사용하는 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  else
        cat /etc/passwd | egrep -v -i "nologin|false" | grep -v root | awk -F":" 'length($6) > 0' | awk -F":" '$6 == "/"' >> $CREATE_FILE 2>&1
        echo "BAD" >> DHOME_pan.fou
  fi
        

  echo " " >> $CREATE_FILE 2>&1

  if [ ! -f Home.fou ]
    then
      echo "GOOD" >> DHOME_pan.fou
    else
      echo "BAD" >> DHOME_pan.fou
      rm -rf Home.fou
  fi
  
  if [ `cat DHOME_pan.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-59. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-59. 결과 : 취약" >> $CREATE_FILE 2>&1
      
	  
  fi
  rm -rf DHOME_pan.fou
 rm -rf no_Home.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_60() {
  echo -n "U-60. 숨겨진 파일 및 디렉터리 검색 및 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-60. 숨겨진 파일 및 디렉터리 검색 및 제거 " >> $CREATE_FILE 2>&1
  echo ":: 디렉터리 내 숨겨진 파일을 확인하여, 불필요한 파일 삭제를 완료한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 숨겨진 파일 및 디렉터리 현황" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

#find /tmp -name ".*" -ls  > hidden-file.fou
  find /home -name ".*" -ls | egrep -v ".bash|viminfo|mozilla" >> hidden-file.fou
  find /usr -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.fou
  find /var -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.fou
  find /bin -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.fou
  find /sbin -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.fou
  echo " " >> $CREATE_FILE 2>&1

  if [ -s hidden-file.fou ]
    then
      cat hidden-file.fou >> $CREATE_FILE 2>&1
      echo " " >> $CREATE_FILE 2>&1
      echo "★ U-60. 결과 : 수동점검" >> $CREATE_FILE 2>&1
      rm -rf hidden-file.fou
    else
      echo "★ U-60. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}




U_19() {
  echo -n "U-19. Finger 서비스 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-19. Finger 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: Finger 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="finger"
  
	echo "① finger 포트 활성화 상태" >> $CREATE_FILE 2>&1
	echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ `netstat -na | grep :79 | grep -i listen | wc -l` -ge 1 ]
		then
			echo "☞ finger 서비스 포트가 활성화되어 있습니다." >>$CREATE_FILE 2>&1
			echo "BAD" >> service.fou
	else
		echo " " >> $CREATE_FILE 2>&1
		
		echo "☞ finger 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	
  echo "② inetd.conf 파일에서 finger 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "☞ /etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "☞ finger 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "④ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d디렉터리에 finger 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.fou

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.fou
        else
          echo "BAD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.fou
              else
                echo "GOOD" >> service.fou
            fi
          done
        else
          echo "GOOD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  if [ `cat service.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-19. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-19. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_20() {
  echo -n "U-20. Anonymous FTP 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-20. Anonymous FTP 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: Anonymous FTP (익명 ftp) 접속을 차단한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

 
  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  echo "① FTP 프로세스/포트 활성화 상태" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  ps -ef | grep "ftp" | grep -v "grep" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  netstat -na | grep "\*.21 " | grep -i "listen" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  
  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '#' | grep ftp  | grep -v "tftp" |  wc -l` -gt 0  ]
        then
          echo "ftp 서비스가 활성화되어 있습니다." >> ftpps.fou
      fi
  fi

  ps -ef | grep ftp | grep -v grep | egrep -v "tftp|sftp" >> ftpps.fou
  echo " " >> $CREATE_FILE 2>&1

  anony_vsftp="/etc/vsftpd/vsftpd.conf /etc/vsftpd.conf"
 
  echo "② FTP Anonymous 관련 현황" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  echo "■ /etc/passwd 파일 ftp 계정 존재여부" >> $CREATE_FILE 2>&1
  if [ `cat ftpps.fou | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      if [ -f /etc/passwd ]
        then
		  if [ `cat /etc/passwd | grep -i "ftp" | wc -l` -ge 1 ]
		  then
		    cat /etc/passwd | grep "ftp" >> $CREATE_FILE 2>&1
		  else
		    echo "☞ /etc/passwd 파일 내 ftp 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		  fi
        else
          echo "☞ /etc/passwd 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
      fi  
	  echo " " >> $CREATE_FILE 2>&1

	  echo " " > vscheck.fou
	  
	  for file in $anony_vsftp
	   do
		  if [ -f $file ]
			then
			  echo "■ "$file"파일 내 anonymous enable 설정" >> $CREATE_FILE 2>&1
			  cat $file | grep -i "anonymous_enable" >> $CREATE_FILE 2>&1
			  echo "vsftp" >> vscheck.fou
		  fi
	   done 
	   #vsftpd 확인 추가
	echo " " >> $CREATE_FILE 2>&1
	
	if [ `cat vscheck.fou | grep -i "vsftp" | wc -l` -eq 0 ]
	then
	   echo "☞ vsftp 관련 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	   
    else
      echo "☞ ftp 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  
  echo " " > anony.fou

  if [ `cat ftpps.fou | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      if [ `grep -v "^ *#" /etc/passwd | grep "ftp" | egrep -v "false|nologin" | wc -l` -gt 0 ]
        then
          echo "BAD" >> anony.fou
      else
          echo "GOOD" >> anony.fou
      fi
	  
	  for file in $anony_vsftp
	   do
		  if [ -f $file ]
			then
			  if [ `cat $file | grep -i "anonymous_enable" | grep -i "yes" | grep -v "^#" | wc -l` -eq 0 ]
			   then
			     echo "GOOD" >> anony.fou
			   else
			     echo "BAD" >> anony.fou
			  fi
		  fi
	   done  
	  #vsftp 확인 추가
	  
    else
      echo "GOOD" >> anony.fou
  fi

  if [ `cat anony.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-20. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-20. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
  

  rm -rf anony.fou	
  rm -rf vscheck.fou
  rm -rf ftpps.fou


  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_21() {
  echo -n "U-21. r 계열 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-21. r 계열 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: r 계열 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="shell|login|exec|rsh|rlogin|rexec"
	echo " " > 21.fou
  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 서비스 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "☞ r 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d디렉터리에 r 계열 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="shell|login|exec|rsh|rlogin|rexec"

  echo "① inetd.conf 파일에서 'r' commnad 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/inetd.conf ]
    then
      cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "★ U-21. 결과 : 취약" >> 21.fou 2>&1
                
              else
                echo "★ U-21. 결과 : 양호" >> 21.fou 2>&1
            fi
          done
        else
          echo "★ U-21. 결과 : 양호" >> 21.fou 2>&1
      fi
    elif [ -f /etc/inetd.conf ]
      then
        if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
          then
            echo "★ U-21. 결과 : 양호" >> 21.fou 2>&1
          else
            echo "★ U-21. 결과 : 취약" >> 21.fou 2>&1
            
        fi
      else
        echo "★ U-21. 결과 : 양호" >> 21.fou 2>&1
  fi
    if [ `cat 21.fou | grep "BAD" | wc -l` -eq 0 ]
    then
       echo "★ U-21. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
       echo "★ U-21. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
  
	rm -rf 21.fou 
  rm -rf r_temp

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

#20150923-01
U_22() {
  echo -n "U-22. cron 파일 소유자 및 권한 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-22. cron 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: cron 접근제어 파일 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo ":: 파일이 존재하지 않는경우 파일 정보를 출력하지 않습니다." >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
 
  echo "① Cron.allow, Cron.deny 파일 정보" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ -f /etc/cron.allow ]
    then
	 ls -al /etc/cron.allow >> $CREATE_FILE 2>&1
	 if [ \( `ls -l /etc/cron.allow | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/cron.allow | grep '...-.-----' | wc -l` -eq 1 \) ]; 
	  then 
	   echo "GOOD" > crontab.fou
	  else
	   echo "BAD" >> crontab.fou
     fi
  	else
	 if [ -f /etc/cron.deny ]
      then
	   ls -al /etc/cron.deny >> $CREATE_FILE 2>&1
	   echo "BAD" >> crontab.fou
	  else
        echo "GOOD" >> crontab.fou
	 fi
   fi 
	 
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat crontab.fou | grep "GOOD" | wc -l` -ge 1 ]
    then
      echo "★ U-22. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-22. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi



  rm -rf crontab.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_23() {
  echo -n "U-23. DoS 공격에 취약한 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-23. DoS 공격에 취약한 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: DoS 공격에 취약한 echo, discard, daytime, chargen 서비스가 비활성화 된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="echo|discard|daytime|chargen"


  echo "① inetd.conf 파일에서 echo, discard, daytime, chargen 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "☞ /etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "☞ DoS 공격에 취약한 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "③ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d 디렉터리에 DoS에 취약한 서비스 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.fou

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.fou
        else
          echo "BAD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.fou
              else
                echo "GOOD" >> service.fou
            fi
          done
        else
          echo "GOOD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat service.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-23. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-23. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_24() {
  echo -n "U-24. NFS 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-24. NFS 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: NFS 서비스 관련 데몬이 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  if [ `ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
    then
	  ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" >> $CREATE_FILE 2>&1
      if [ -f /etc/exports ]
        then
          cat /etc/exports  >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
      fi
    else
      echo "☞ NFS 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
    
	ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1 

  if [ `ps -ef | egrep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-24. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/exports ]
        then
          if [ `cat /etc/exports | grep -v "^#" | grep "/" | wc -l` -eq 0 ]
            then
              echo "★ U-24. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-24. 결과 : 수동점검" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-24. 결과 : 양호"  >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_25() {
  echo -n "U-25. NFS 접근통제  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-25. NFS 접근통제 " >> $CREATE_FILE 2>&1
  echo ":: NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유를 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  echo "① NFS 접근통제 파일 권한 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
    then
	  ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" >> $CREATE_FILE 2>&1
      if [ -f /etc/exports ]
        then
          cat /etc/exports  >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
      fi
    else
    echo "☞ NFS 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
   
    ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
	
  if [ `ps -ef | egrep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-25. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/exports ]
        then
          if [ `cat /etc/exports | grep -v "^#" | grep "/" | wc -l` -eq 0 ]
            then
              echo "★ U-25. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-25. 결과 : 수동점검" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-25. 결과 : 수동점검"  >> $CREATE_FILE 2>&1
      fi
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_26() {
  echo -n "U-26. automountd 제거  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-26. automountd 제거 " >> $CREATE_FILE 2>&1
  echo ":: automountd 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Automount 데몬 확인." >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  ps -ef | egrep 'automountd|autofs' | egrep -v "grep|statdaemon|emi" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  ls -al /etc/rc*.d/* | grep -i "auto" | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | egrep 'automountd|autofs' | egrep -v "grep|statdaemon|emi"  | wc -l` -eq 0 ]
    then
      echo "☞ automount 데몬이 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | egrep 'automountd|autofs' | egrep -v "grep|statdaemon|emi" | wc -l` -eq 0 ]
    then
      echo "★ U-26. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-26. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_27() {
  echo -n "U-27. RPC 서비스 확인  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-27. RPC 서비스 확인 " >> $CREATE_FILE 2>&1
  echo ":: 불필요한 RPC 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|ruserd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

  echo "① inetd.conf 파일에서 RPC 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "☞ /etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  
  echo "② /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]
        then
          echo "☞ /etc/xinetd.d RPC 서비스가 없음" >> $CREATE_FILE 2>&1
        else
          ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
      fi
    else
      echo "☞ /etc/xinetd.d 디렉터리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d에 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo " " > rpc.fou

  SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|ruserd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> rpc.fou
        else
          echo "BAD" >> rpc.fou
      fi
    else
      echo "GOOD" >> rpc.fou
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> rpc.fou
              else
                echo "GOOD" >> rpc.fou
            fi
          done
        else
          echo "GOOD" >> rpc.fou
      fi
    else
      echo "GOOD" >> rpc.fou
  fi

  if [ `cat rpc.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-27. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-27. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf rpc.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_28() {
  echo -n "U-28. NIS, NIS+ 점검  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-28. NIS, NIS+ 점검 " >> $CREATE_FILE 2>&1
  echo ":: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

  echo "① NIS, NIS+ 서비스 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1  
  
  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
	    echo "☞ NIS, NIS+ 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
	    ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-28. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-28. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_29() {
  echo -n "U-29. tftp, talk 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-29. tftp, talk 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="tftp|talk|ntalk"


  echo "① inetd.conf 파일에서 tftp, talk 상태" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "☞ /etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "☞ tftp, talk 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "③ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "☞ xinetd.d 디렉터리에 tftp, talk, ntalk 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.fou

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.fou
        else
          echo "BAD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.fou
              else
                echo "GOOD" >> service.fou
            fi
          done
        else
          echo "GOOD" >> service.fou
      fi
    else
      echo "GOOD" >> service.fou
  fi

  if [ `cat service.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-29. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-29. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.fou


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_30() {
  echo -n "U-30. Sendmail 버전 점검  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-30. Sendmail 버전 점검 " >> $CREATE_FILE 2>&1
  echo ":: Sendmail 버전이 8.15.2 이상인 경우 양호" >> $CREATE_FILE 2>&1
  echo ":: 로컬(127.0.0.1)에서만 Sendmail 서비스를 사용할 경우 버전 및 설정에 관계없이 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ Sendmail 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② SMTP 서비스 포트 활성화 여부 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -ge 1 ]
    then
	    smtpport=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	    if [ `netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ]
	      then
		      netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
			  echo "" >> $CREATE_FILE 2>&1
		      echo "☞ SMTP 서비스 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "SMTPENABLE" >> smtpenable.fou 2>&1
		   
		   else
				if [ `netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "LISTEN" | wc -l` -ge 1 ]
				  then
					netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ 로컬에서 사용하는 SMTP 서비스의 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou
				  else
					netstat -na | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ SMTP 포트가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou 2>&1
				fi
		fi	
		
    else
	    if [ `netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ] 
		  then 
			netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1 
			echo "☞ SMTP 기본 포트가 활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "SMTPENABLE" > smtpenable.fou 2>&1 		   
		  else 
			if [ `netstat -na | grep "127\.0\.0\.1\:25" | grep -i "LISTEN" | wc -l` -ge 1 ]
			  then
				netstat -na | grep "127\.0\.0\.1\:25" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
				echo "☞ 로컬에서 사용하는 SMTP 서비스의 기본포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			  else
				echo "☞ SMTP 기본 포트가 비활성화되어 있습니다.">> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			fi
		fi 
   fi 
   
   echo "" >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② sendmail 버전확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-30. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `grep -v '^ *#' /etc/mail/sendmail.cf | egrep "DZ8.15.2" | wc -l ` -eq 1 ]
            then
              echo "★ U-30. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-30. 결과 : 수동점검" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-30. 결과 : 수동점검" >> $CREATE_FILE 2>&1
      fi
  fi

  rm -f smtpenable.fou 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_31() {
  echo -n "U-31. 스팸 메일 릴레이 제한  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-31. 스팸 메일 릴레이 제한 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo ":: Sendmail 버전이 8.9 이상일 경우 디폴트로 릴레이 제한이 설정되어 있어 양호함" >> $CREATE_FILE 2>&1   
  echo ":: 로컬(127.0.0.1)에서만 Sendmail 서비스를 사용할 경우 버전 및 설정에 관계없이 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ Sendmail 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② SMTP 서비스 포트 활성화 여부 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -ge 1 ]
    then
	    smtpport=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	    if [ `netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ]
	      then
		      netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
			  echo "" >> $CREATE_FILE 2>&1
		      echo "☞ SMTP 서비스 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "SMTPENABLE" >> smtpenable.fou 2>&1
		   
		   else
				if [ `netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "LISTEN" | wc -l` -ge 1 ]
				  then
					netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ 로컬에서 사용하는 SMTP 서비스의 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou
				  else
					netstat -na | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ SMTP 포트가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou 2>&1
				fi
		fi	
		
    else
	    if [ `netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ] 
		  then 
			netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1 
			echo "☞ SMTP 기본 포트가 활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "SMTPENABLE" > smtpenable.fou 2>&1 		   
		  else 
			if [ `netstat -na | grep "127\.0\.0\.1\:25" | grep -i "LISTEN" | wc -l` -ge 1 ]
			  then
				netstat -na | grep "127\.0\.0\.1\:25" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
				echo "☞ 로컬에서 사용하는 SMTP 서비스의 기본포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			  else
				echo "☞ SMTP 기본 포트가 비활성화되어 있습니다.">> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			fi
		fi 
   fi 
   
   echo "" >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-31. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -v "^#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
            then
              echo "★ U-31. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-31. 결과 : 취약" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-31. 결과 : 수동점검" >> $CREATE_FILE 2>&1
      fi
  fi

  rm -f smtpenable.fou 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_32() {
  echo -n "U-32. 일반사용자의 Sendmail 실행 방지  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-32. 일반사용자의 Sendmail 실행 방지 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정 된 경우 양호" >> $CREATE_FILE 2>&1
  echo ":: 로컬(127.0.0.1)에서만 Sendmail 서비스를 사용할 경우 버전 및 설정에 관계없이 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ Sendmail 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  
  echo "② SMTP 서비스 포트 활성화 여부 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -ge 1 ]
    then
	    smtpport=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	    if [ `netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ]
	      then
		      netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
			  echo "" >> $CREATE_FILE 2>&1
		      echo "☞ SMTP 서비스 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "SMTPENABLE" >> smtpenable.fou 2>&1
		   
		   else
				if [ `netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "LISTEN" | wc -l` -ge 1 ]
				  then
					netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ 로컬에서 사용하는 SMTP 서비스의 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou
				  else
					netstat -na | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ SMTP 포트가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou 2>&1
				fi
		fi	
		
    else
	    if [ `netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ] 
		  then 
			netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1 
			echo "☞ SMTP 기본 포트가 활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "SMTPENABLE" > smtpenable.fou 2>&1 		   
		  else 
			if [ `netstat -na | grep "127\.0\.0\.1\:25" | grep -i "LISTEN" | wc -l` -ge 1 ]
			  then
				netstat -na | grep "127\.0\.0\.1\:25" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
				echo "☞ 로컬에서 사용하는 SMTP 서비스의 기본포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			  else
				echo "☞ SMTP 기본 포트가 비활성화되어 있습니다.">> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			fi
		fi 
   fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-32. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "^#" |wc -l ` -eq 1 ]
            then
              echo "★ U-32. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-32. 결과 : 취약" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-32. 결과 : 수동점검" >> $CREATE_FILE 2>&1
      fi
  fi

  rm -f smtpenable.fou 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_33() {
  echo -n "U-33. DNS 보안 버전 패치  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-33. DNS 보안 버전 패치 " >> $CREATE_FILE 2>&1
  echo ":: DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 DNSPR=`ps -ef | egrep -i "/named|/in.named" | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
  DNSPR=`echo $DNSPR | awk '{print $1}'`

  if [ `ps -ef | egrep -i "/named|/in.named" | grep -v grep | wc -l` -gt 0 ]
    then
      if [ -f $DNSPR ]
        then
          echo "① BIND 버전 확인" >> $CREATE_FILE 2>&1
          echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
          $DNSPR -v | grep BIND >> $CREATE_FILE 2>&1
        else
          echo "☞ $DNSPR 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo "☞ DNS 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-33. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f $DNSPR ]
        then
          if [ `$DNSPR -v | grep BIND | egrep '8.4.6 | 8.4.7 | 9.2.8-P1 | 9.3.4-P1 | 9.4.1-P1 | 9.5.0a6 | 9.9.9-P4 | 9.10.4-P4 | 9.11.0-P1' |wc -l` -gt 0 ]
            then
              echo "★ U-33. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-33. 결과 : 수동점검" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-33. 결과 : 수동점검" >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_34() {
  echo -n "U-34. DNS Zone Transfer 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-34. DNS Zone Transfer 설정 " >> $CREATE_FILE 2>&1
  echo ":: DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ DNS 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i named | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/named.conf 파일의 allow-transfer 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ -f /etc/named.conf ]
      then
        cat /etc/named.conf | grep 'allow-transfer' >> $CREATE_FILE 2>&1
      else
        echo "☞ /etc/named.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
   fi

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/named.boot 파일의 xfrnets 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ -f /etc/named.boot ]
      then
        cat /etc/named.boot | grep "\xfrnets" >> $CREATE_FILE 2>&1
      else
        echo "☞ /etc/named.boot 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
    fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-34. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/named.conf ]
        then
          if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^#" | wc -l` -eq 0 ]
            then
              echo "★ U-34. 결과 : 취약" >> $CREATE_FILE 2>&1
            else
              echo "★ U-34. 결과 : 양호" >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
            then
              if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^#" | wc -l` -eq 0 ]
                then
                  echo "★ U-34. 결과 : 취약" >> $CREATE_FILE 2>&1
                else
                  echo "★ U-34. 결과 : 양호" >> $CREATE_FILE 2>&1
              fi
           else
              echo "★ U-34. 결과 : 수동점검" >> $CREATE_FILE 2>&1
          fi
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_35() {
  echo -n "U-35. Apache 디렉터리 리스팅 제거  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-35. Apache 디렉터리 리스팅 제거 " >> $CREATE_FILE 2>&1
  echo ":: 디렉터리 검색 기능을 사용하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  if [ $web = 'default' ]; then
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-35. 결과 : N/A" >> $CREATE_FILE 2>&1
  else
	if [ $path = 'ok' ]
	then
			if [ `cat $conf |grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#'|wc -l` -eq 0 ]; then
				result1_35='Good'
				echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "DocumentRoot" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ Indexes 옵션이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result1_35='vulnerable'
				echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "DocumentRoot" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ Indexes 옵션이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
	else
		result1_35='interview'
		echo "Indexes 설정 확인" $conf >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
		echo "conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
	fi
	if [ -f $apache/conf.d/userdir.conf ]
	then
		if [ `cat $apache/conf.d/userdir.conf | grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#'| wc -l` -eq 0 ]; then
			result1_35='Good'
			echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot" >> $CREATE_FILE 2>&1
			cat $apache/conf.d/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo '☞ Indexes 옵션이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		else
			echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
			result1_35='vulnerable'
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot" >> $CREATE_FILE 2>&1
			cat $apache/conf.d/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo '☞ Indexes 옵션이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi
	else
		echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
		echo $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
	fi	
	
	if [ $result1_35 = 'vulnerable' ]; then
		echo ' ' >> $CREATE_FILE 2>&1
		echo "★ U-35. 결과 : 취약" >> $CREATE_FILE 2>&1
	elif [ $result1_35 = 'interview' ]; then
		echo ' ' >> $CREATE_FILE 2>&1
		echo "★ U-35. 결과 : 수동점검" >> $CREATE_FILE 2>&1
	else
		echo ' ' >> $CREATE_FILE 2>&1
		echo "★ U-35. 결과 : 양호" >> $CREATE_FILE 2>&1
	fi
  
fi
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_36() {
  echo -n "U-36. Apache 웹 프로세스 권한 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-36. Apache 웹 프로세스 권한 제한 " >> $CREATE_FILE 2>&1
  echo ":: Apache 데몬이 root 권한으로 구동되지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ $web = 'httpd' ];then
		if [ `ps -ef | egrep -i "httpd|apache2" | grep -v grep | grep -v root | wc -l` -eq 0 ]; then
			ps -ef | egrep -i "httpd|apache2" | grep -v grep >>  $CREATE_FILE 2>&1
			echo ' ' >>  $CREATE_FILE 2>&1
			echo '☞ root계정으로 Apache 서비스를 구동하고 있습니다.' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-36. 결과 : 취약" >> $CREATE_FILE 2>&1
		else
			ps -ef | egrep -i "httpd|apache2" | grep -v grep >>  $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo '☞ root계정으로 Apache 서비스를 구동하지 않습니다.' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-36. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
  else
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-36. 결과 : N/A" >> $CREATE_FILE 2>&1	
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_37() {
  echo -n "U-37. Apache 상위 디렉터리 접근 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-37. Apache 상위 디렉터리 접근 금지 " >> $CREATE_FILE 2>&1
  echo ":: 상위 디렉터리에 이동 제한을 설정한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ $web = 'default' ]; then
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-37. 결과 : N/A" >> $CREATE_FILE 2>&1	
  else
	if [ $path = 'ok' ]
			then
				if [ `cat $conf | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					result_37='Good'
					echo "AllowOverride 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					result_37='vulnerable'
					echo "AllowOverride 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				result_37='interview'
				echo "Indexes 설정 확인" >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				echo "conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/conf.d/userdir.conf ]
			then
				if [ `cat $apache/conf.d/userdir.conf | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					result_37='Good'
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					result_37='vulnerable'
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				echo "☞" $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		
		if [ $result_37 = 'vulnerable' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-37. 결과 : 취약" >> $CREATE_FILE 2>&1
		elif [ $result_37 = 'interview' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-37. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-37. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
	fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_38() {
  echo -n "U-38. Apache 불필요한 파일 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-38. Apache 불필요한 파일 제거 " >> $CREATE_FILE 2>&1
  echo ":: 메뉴얼 파일 및 디렉터리가 제거되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ $web = 'httpd' ];then
	if [ $path = 'ok' ]; then
		if [ `find "$svrroot" -name 'manual'|wc -l` -eq 0 ]
		then
			echo "☞ Manual 디렉터리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
			result38='Good'
		else
			find "$svrroot" -name 'manual' >> $CREATE_FILE
			result38='Vulnerability'
		fi
		echo ' ' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		if [ $result38 = 'Good' ]; then
			echo "★ U-38. 결과 : 양호" >> $CREATE_FILE 2>&1	
		else
			echo "★ U-38. 결과 : 취약" >> $CREATE_FILE 2>&1	
		fi
	else
		echo "Manual 디렉터리 확인" $conf >> $CREATE_FILE 2>&1
		echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
		echo "☞ conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo "★ U-38. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
	fi
  else
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-38. 결과 : N/A" >> $CREATE_FILE 2>&1	
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_39() {
  echo -n "U-39. Apache 링크 사용금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-39. Apache 링크 사용금지 " >> $CREATE_FILE 2>&1
  echo ":: 심볼릭 링크, aliases 사용을 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ $web = 'default' ]; then
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-39. 결과 : N/A" >> $CREATE_FILE 2>&1	
  else
		if [ $path = 'ok' ]
		then
			if [ `cat $conf | grep -i "FollowSymLinks" | grep -iv "\-FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
				result_39='Good'
				echo "FollowSymLinks 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "FollowSymLinks " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ FollowSymLinks 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result_39='vulnerable'
				echo "FollowSymLinks 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "FollowSymLinks " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ FollowSymLinks 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
		else
			result_39='interview'
			echo "FollowSymLinks 설정 확인" $conf >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞ conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/conf.d/userdir.conf ]
		then
			if [ `cat $apache/conf.d/userdir.conf | grep -i "FollowSymLinks" | grep -iv "\-FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
				result_39='Good'
				echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ FollowSymLinks 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result_39='vulnerable'
				echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ FollowSymLinks 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
		else
			echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞" $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi		
		
		if [ $result_39 = 'vulnerable' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-39. 결과 : 취약" >> $CREATE_FILE 2>&1
		elif [ $result_39 = 'interview' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-39. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-39. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
	fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_40() {
  echo -n "U-40. Apache 파일 업로드 및 다운로드 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-40. Apache 파일 업로드 및 다운로드 제한 " >> $CREATE_FILE 2>&1
  echo ":: 파일 업로드 및 다운로드를 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
 
    result_40='bad'
    
	if [ $web = 'default' ];
	then
		echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
	else
		if [ $path = 'ok' ]
		then 
			if [ `cat $conf | grep -i "LimitRequestBody" | grep -v '^#' | wc -l` -eq 0 ];
			then
				echo "LimitRequestBody 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "LimitRequestBody " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ 파일 업로드 및 다운로드 제한 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result_40='good'
				echo "LimitRequestBody 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "LimitRequestBody " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ LimitRequestBody 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
		else
			result_40='interview'
			echo "LimitRequestBody 설정 확인" >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞ conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi		
	
		if [ -f $apache/conf.d/userdir.conf ]
		then
			if [ `cat $apache/conf.d/userdir.conf | grep -i "LimitRequestBody" | grep -v '^#' | wc -l` -eq 0 ]; then
				echo "LimitRequestBody 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "LimitRequestBody " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ FollowSymLinks 설정이 적용되지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result_40='good'
				echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $apache/conf.d/userdir.conf | egrep -i "LimitRequestBody " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ LimitRequestBody 설정이 적용되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
		else
			echo "LimitRequestBody 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞" $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi	
	fi

	if [ $web = 'default' ];
	then
		echo "★ U-40. 결과 : N/A" >> $CREATE_FILE 2>&1	
	else 
		if [ $result_40 = 'good' -o $result_40 = 'interview' ]
		then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-40. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-40. 결과 : 취약" >> $CREATE_FILE 2>&1
		fi
	fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_41() {
  echo -n "U-41. Apache 웹 서비스 영역의 분리 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-41. Apache 웹 서비스 영역의 분리 " >> $CREATE_FILE 2>&1
  echo ":: DocumentRoot를 별도의 디렉터리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ $web = 'default' ]; then
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-41. 결과 : N/A" >> $CREATE_FILE 2>&1	
  else
		if [ $path = 'ok' ]
		then
			if [ `cat $conf | grep -i "DocumentRoot" | grep -v '#' | grep -i "$apache/htdocs" | wc -l` -eq 0 ]; then
				result_41='Good'
				echo "DocumentRoot 설정 확인" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ 웹 서비스 영역이 분리되어 있습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			else
				result_41='vulnerable'
				echo "DocumentRoot 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo '☞ 웹 서비스 영역이 분리되어있지 않습니다.' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi
		else
			result_41='interview'
			echo "DocumentRoot 설정 확인" >> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞ conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/conf.d/userdir.conf ]
			then
				if [ `cat $apache/conf.d/userdir.conf | grep -i "DocumentRoot" | grep -v '#' | grep -i "$apache/htdocs" | wc -l` -eq 0 ]; then
					result_41='Good'
					echo "DocumentRoot 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ 웹 서비스 영역이 분리되어 있습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					result_41='vulnerable'
					echo "DocumentRoot 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ 웹 서비스 영역이 분리되어 있지 않습니다.' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "DocumentRoot 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				echo "☞" $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		
		if [ $result_41 = 'vulnerable' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-41. 결과 : 취약" >> $CREATE_FILE 2>&1
		elif [ $result_41 = 'interview' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-41. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-41. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
	fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_61() {
  echo -n "U-61. ssh 원격접속 허용 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-61. ssh 원격접속 허용 " >> $CREATE_FILE 2>&1
  echo ":: 원격 접속 시 SSH 프로토콜을 사용하는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 프로세스 데몬 동작 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	  then
		  echo "☞ SSH 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	  else
		  ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② 서비스 포트 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  echo " " > ssh-result.fou

  ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"

  for file in $ServiceDIR
    do
	    if [ -f $file ]
	      then
		      if [ `cat $file | grep "^Port" | grep -v "^#" | wc -l` -gt 0 ]
		        then
			        cat $file | grep "^Port" | grep -v "^#" | awk '{print "SSH 설정파일('${file}'): " $0 }' >> ssh-result.fou
			        port1=`cat $file | grep "^Port" | grep -v "^#" | awk '{print $2}'`
			        echo $port1 >> port1-search.fou
		        else
			        echo "☞ SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)" >> ssh-result.fou
		      fi
	    fi
    done

  if [ `cat ssh-result.fou | grep -v "^ *$" | wc -l` -gt 0 ]
    then
	    cat ssh-result.fou | grep -v "^ *$" >> $CREATE_FILE 2>&1
    else
	    echo "☞ SSH 설정파일: 설정 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1

  # 서비스 포트 점검
  echo "③ 서비스 포트 활성화 여부 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ -f port1-search.fou ]
    then
	    if [ `netstat -nat | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
		      echo "☞ SSH 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	      else
		      netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    fi
    else
	    if [ `netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
		      echo "☞ SSH 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	      else
		      netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    fi
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f port1-search.fou ]
    then
      if [ `netstat -nat | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
        then
          echo "★ U-61. 결과 : 취약" >> $CREATE_FILE 2>&1
        else
          echo "★ U-61. 결과 : 양호" >> $CREATE_FILE 2>&1
      fi
    else
	    if [ `netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
	        echo "★ U-61. 결과 : 취약" >> $CREATE_FILE 2>&1
	      else
	        echo "★ U-61. 결과 : 양호" >> $CREATE_FILE 2>&1
	    fi
	fi


  rm -rf ssh-result.fou port1-search.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_62() {
  echo -n "U-62. ftp 서비스 확인 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-62. ftp 서비스 확인 " >> $CREATE_FILE 2>&1
  echo ":: FTP 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  find /etc -name "proftpd.conf" > proftpd.fou
  find /etc -name "vsftpd.conf" > vsftpd.fou
  profile=`cat proftpd.fou`
  vsfile=`cat vsftpd.fou`

  echo "① /etc/services 파일에서 포트 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
    then
	    cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
    else
	    echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)" >> $CREATE_FILE 2>&1
  fi

  if [ -s vsftpd.fou ]
    then
	    if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	      then
		      cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	      else
		      echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)" >> $CREATE_FILE 2>&1
	    fi
    else
	    echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다." >> $CREATE_FILE 2>&1
  fi


  if [ -s proftpd.fou ]
    then
	    if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	      then
		      cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	      else
		      echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트 사용중)" >> $CREATE_FILE 2>&1
	    fi
    else
	    echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② 서비스 포트 활성화 여부 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  ################# /etc/services 파일에서 포트 확인 #################

  if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
    then
	    port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	    
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	      then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable" > ftpenable.fou
		else
			  echo "ftp disable">> ftpenable.fou
	    fi
    else
	    netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    echo "ftp enable" > ftpenable.fou
  fi

  ################# vsftpd 에서 포트 확인 ############################

  if [ -s vsftpd.fou ]
    then
	    if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	      then
		      port=21
	      else
		      port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	    fi
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	      then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable" >> ftpenable.fou
		  else
			  echo "ftp disable" >> ftpenable.fou
	    fi
	  else
	    echo "ftp disable" >> ftpenable.fou
  fi

  ################# proftpd 에서 포트 확인 ###########################

  if [ -s proftpd.fou ]
    then
	    port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	    
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	        then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable"  >> ftpenable.fou
		    else
		      echo "ftp disable" >> ftpenable.fou
	    fi
	  else
	    echo "ftp disable" >> ftpenable.fou
  fi
  
	if [ `cat ftpenable.fou | grep -i "ftp disable" | wc -l` -eq 3 ]
		then
			echo "☞ 서비스 포트가 활성화 되어 있지 않습니다." >> $CREATE_FILE 2>&1
	fi 
  echo " " >> $CREATE_FILE 2>&1
  
  echo "③ 서비스 프로세스 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ `ps -ef | grep ftp | grep -v "grep" | wc -l` -eq 0]
	then
		ps -ef | grep ftp | grep -v "grep" >> $CREATE_FILE 2>&1
		echo "☞ FTP 서비스 프로세스가 작동하고있지 않습니다" >> $CREATE_FILE 2>&1
		echo "ftp disble"  >> ftpenable.fou
	else
	    ps -ef | grep ftp | grep -v "grep" >> $CREATE_FILE 2>&1
		echo "ftp enable" >> ftpenable.fou
  fi  
  
  echo " " >> $CREATE_FILE 2>&1
  
  if [ `cat ftpenable.fou | grep "enable" | wc -l` -gt 1 ]
    then
      echo "★ U-62. 결과 : 취약" >> $CREATE_FILE 2>&1
    else
      echo "★ U-62. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  rm -rf proftpd.fou vsftpd.fou


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_63() {
  echo -n "U-63. ftp 계정 shell 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-63. ftp 계정 shell 제한 " >> $CREATE_FILE 2>&1
  echo ":: ftp 계정에 /bin/false 쉘이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

   echo "① ftp 계정 쉘 확인(ftp 계정에 false 또는 nologin 설정시 양호)" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | egrep "false|nologin" | wc -l` -gt 0 ]
    then
      result63='good'
    else
      result63='Vulnerability'
  fi  
  
  if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
    then
	    cat /etc/passwd | awk -F: '$1=="ftp"' >> $CREATE_FILE 2>&1
    else
	    echo "☞ ftp 계정이 존재하지 않습니다.(GOOD)" >> $CREATE_FILE 2>&1
		result63='good'
  fi
  
  if [ $result63 = 'good' ]; then
	result63='양호'
  else
	result63='취약'
  fi
  
	 echo " " >> $CREATE_FILE 2>&1
  echo "★ U-63. 결과 : "$result63 >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_64() {
  echo -n "U-64. Ftpusers 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-64. Ftpusers 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① ftpusers 파일의 소유자 및 권한 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
 
  if [ -f /etc/ftpd/ftpusers ]
    then
      ls -alL /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/ftpd/ftpusers 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/ftpusers ]
    then
      ls -alL /etc/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/ftpusers 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd.ftpusers ]
    then
      ls -alL /etc/vsftpd.ftpusers  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/vsftpd.ftpusers 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

   echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd/ftpusers ]
    then
      ls -alL /etc/vsftpd/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/vsftpd/ftpusers 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd.user_list ]
    then
      ls -alL /etc/vsftpd.user_list >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/vsftpd.user_list 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd/user_list ]
    then
      ls -alL /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/vsftpd/user_list 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "  " > ftpusers.fou

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/ftpd/ftpusers ]
    then
      if [ `ls -alL /etc/ftpd/ftpusers | awk '{print $1}' | grep '...-.-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
     fi
    else
      echo "no-file"  >> ftpusers.fou
  fi

  if [ -f /etc/ftpusers ]
    then
      if [ `ls -alL /etc/ftpusers | awk '{print $1}' | grep '...-.-----'| wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
      fi
    else
      echo "no-file"  >> ftpusers.fou
  fi

  if [ -f /etc/vsftpd.ftpusers ]
    then
      if [ `ls -alL /etc/vsftpd.ftpusers | awk '{print $1}' | grep '...-.-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
      fi
    else
      echo "no-file"  >> ftpusers.fou
  fi

  if [ -f /etc/vsftpd/ftpusers ]
    then
      if [ `ls -alL /etc/vsftpd/ftpusers | awk '{print $1}' | grep '...-.-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
      fi
    else
      echo "no-file"  >> ftpusers.fou
  fi
  
  if [ -f /etc/vsftpd.user_list ]
    then
      if [ `ls -alL /etc/vsftpd.user_list | awk '{print $1}' | grep '...-.-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
      fi
    else
      echo "no-file"  >> ftpusers.fou
  fi
  

 if [ -f /etc/vsftpd/user_list ]
    then
      if [ `ls -alL /etc/vsftpd/user_list | awk '{print $1}' | grep '...-.-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.fou
        else
          echo "GOOD" >> ftpusers.fou
      fi
    else
      echo "no-file"  >> ftpusers.fou
  fi


  if [ `cat ftpusers.fou | grep "BAD" | wc -l` -gt 0 ]
    then
      echo "★ U-64. 결과 : 취약" >> $CREATE_FILE 2>&1
    else
      echo "★ U-64. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi

  rm -rf ftpusers.fou


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_65() {
  echo -n "U-65. Ftpusers 파일 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-65. Ftpusers 파일 설정 " >> $CREATE_FILE 2>&1
  echo ":: FTP 서비스가 비활성화 되어 있거나, 활성화 시 root 계정 접속을 차단한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  if [ -f ftpenable.fou ] 
   then 
     if [ `cat ftpenable.fou | grep "enable" | wc -l` -gt 0 ]
      then
       if [ -f /etc/ftpd/ftpusers ]
        then
          echo "■ /etc/ftpd/ftpusers 파일 설정 값" >> $CREATE_FILE 2>&1
		  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
          cat /etc/ftpd/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/ftpd/ftpusers  파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi
	  fi	

      echo " " >> $CREATE_FILE 2>&1

	  
	  find /etc -name "vsftpd.conf" > vsftpd.fou
	  vsfile=`cat vsftpd.fou`
  
  	  if [ -s vsftpd.fou ]
		then
          echo "■ `echo $vsfile` 파일 설정 값" >> $CREATE_FILE 2>&1
		  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		  cat $vsfile | grep -v '^#' | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "☞ vsftpd.conf 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi
  
      if [ -f /etc/ftpusers ]
        then
          echo "■ /etc/ftpuser 파일 설정 값" >> $CREATE_FILE 2>&1
		  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
          cat /etc/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
		  if [ -f /etc/vsftpd/ftpusers ]
			then
				echo "■ /etc/ftpuser 파일 설정 값" >> $CREATE_FILE 2>&1
				echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
				cat /etc/vsftpd/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				echo "☞ /etc/ftpusers 및 /etc/vsftpd/ftpusers 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
		fi
      fi
	
      if [ -f /etc/vsftpd/user_list ]
        then
          echo "■ /etc/vsftpd/user_list 파일 설정 값" >> $CREATE_FILE 2>&1
		  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
		  cat /etc/vsftpd/user_list | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/vsftpd/user_list 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi
  
  else
    echo "☞ ftp 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " > ftp.fou

  FILES="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list"

  for check_file in $FILES
	do
	  if [ -f $check_file ]
	    then 
		  cat $check_file 2>/dev/null | grep -i root | grep -v "^#" >> ftp.fou
	  fi
	done

  echo " " >> $CREATE_FILE 2>&1

  if [ -f ftpenable.fou ]
   then 
    if [ `cat ftpenable.fou | grep "enable" | wc -l` -gt 0 ]
     then
       if [ `cat ftp.fou | grep root | grep -v grep | wc -l` -eq 0 ]
        then
          echo "★ U-65. 결과 : 취약" >> $CREATE_FILE 2>&1
        else
          echo "★ U-65. 결과 : 양호" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-65. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi
fi
  rm -rf ftpenable.fou ftp.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_66() {
  echo -n "U-66. at 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-66. at 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: at 접근제어 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
   
  echo "① at.allow, at.deny 파일 정보" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ -f /etc/at.allow ]
   then
	ls -al /etc/at.allow >> $CREATE_FILE 2>&1
	 if [ \( `ls -l /etc/at.allow | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/at.allow | grep '...-.-----' | wc -l` -eq 1 \) ]; 
	  then 
	   echo "GOOD" > U-66.fou
	  else
	   echo "BAD" >> U-66.fou
     fi
  else
	 if [ -f /etc/at.deny ]
      then
	   ls -al /etc/at.deny >> $CREATE_FILE 2>&1
	   echo "BAD" >> U-66.fou
	  else
       echo "GOOD" >> U-66.fou
	 fi
  fi 
    
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat U-66.fou | grep "GOOD" | wc -l` -ge 1 ]
    then
      echo "★ U-66. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-66. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf U-66.fou
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_67() {
  echo -n "U-67. SNMP 서비스 구동 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-67. SNMP 서비스 구동 점검 " >> $CREATE_FILE 2>&1
  echo ":: SNMP 서비스를 사용하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "" > U-67.fou 2>&1
  
  echo "① SNMP 서비스 포트 활성화 여부 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  
    if [ `cat /etc/services | awk -F" " '$1=="snmp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -ge 1 ]
		then
	    snmpport=`cat /etc/services | awk -F" " '$1=="snmp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	    if [ `netstat -nat  | grep -w ":$snmpport " | grep -i "^udp" | grep -i "LISTEN" | wc -l` -ge 1 ]
	      then
		      netstat -nat | grep -w ":$snmpport " | grep -i "^udp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
			  echo "" >> $CREATE_FILE 2>&1
		      echo "☞ SNMP 서비스 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "BAD" > U-67.fou 2>&1
		   
		   else
			  netstat -nat | grep -w ":$snmpport " | grep -i "^udp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo " " >> $CREATE_FILE 2>&1
			  echo "☞ SNMP 서비스 포트가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "GOOD" > U-67.fou 2>&1
		fi	
	else
		if [ `netstat -na | grep -w "\:161 " | grep -i "^udp" | grep -i "LISTEN" | wc -l` -ge 1 ] 
		  then 
			netstat -na | grep -w "\:161 " | grep -i "^udp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1 
			echo "☞ SNMP 기본 포트가 활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "BAD" > smtpenable.fou 2>&1 
		   
		  else 
			echo "☞ SNMP 기본 포트가 비활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "GOOD" > smtpenable.fou 
		fi  
	fi
		
  echo "② SNMP 서비스 구동 여부" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep snmp | grep -v "dmi" | egrep -v "grep|snmpd|disabled" | wc -l` -eq 0 ]
    then
      echo "☞ SNMP가 비활성화되어 있습니다. "  >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  echo "GOOD" > U-67.fou 2>&1
	  
    else
      ps -ef | grep snmp | grep -v "dmi" | egrep -v "grep|snmpd|disabled" >> $CREATE_FILE 2>&1
	  echo "BAD" >> U-67.fou 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
    ls -al /etc/rc*.d/* | grep -i snmp | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1

  if [ `cat U-67.fou | grep "GOOD" | wc -l` -ge 1 ]
    then
      echo "★ U-67. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-67. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf U-67.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_68() {
  echo -n "U-68. SNMP 서비스 Community String의 복잡성 설정 >>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-68. SNMP 서비스 Community string의 복잡성 설정 " >> $CREATE_FILE 2>&1
  echo ":: SNMP Community 이름이 public, private 가 아닌 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  echo "① SNMP 서비스 여부 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -ge 1 ]
    then
    	echo " " >> $CREATE_FILE 2>&1
    	ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" >> $CREATE_FILE 2>&1
    	echo " " >> $CREATE_FILE 2>&1
    	echo "☞ SNMP가 활성화되어 있습니다. "  >> $CREATE_FILE 2>&1
  
  echo " " >> $CREATE_FILE 2>&1

  echo "② 설정파일 CommunityString 현황 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
    
  SPCONF_DIR="/etc/snmpd.conf /etc/snmpdv3.conf /etc/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/sma/snmp/snmpd.conf"

 for file in $SPCONF_DIR
 do
  if [ -f $file ]
  then
     echo "③ "$file"파일 내 CommunityString 설정" >> $CREATE_FILE 2>&1
     echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
     echo " " >> $CREATE_FILE 2>&1
     cat $file | grep -i -A1 -B1 "Community" | grep -v "^#" >> $CREATE_FILE 2>&1
     echo " " >> $CREATE_FILE 2>&1
  fi
 done 
  
  echo "★ U-68. 결과 : 수동점검" >> $CREATE_FILE 2>&1  
  
else
  echo "☞ SNMP가 비활성화되어 있습니다. "  >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "★ U-68. 결과 : 양호" >> $CREATE_FILE 2>&1
fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_69() {
  echo -n "U-69. 로그온 시 경고 메시지 제공 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-69. 로그온 시 경고 메시지 제공 " >> $CREATE_FILE 2>&1
  echo ":: 서버 및 Telnet 서비스에 로그온 메시지가 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  #170131
  if [ -f /etc/issue.net ]
  then
		echo "■ /etc/issue.net 확인(서버정보 출력여부 확인)" >> $CREATE_FILE 2>&1
		echo "☞ 서비스별 배너 경로 설정에 /etc/issue.net이 설정되어 있지 않으면 무관함 " >> $CREATE_FILE 2>&1
		cat /etc/issue.net >> $CREATE_FILE 2>&1
		echo "  " >> $CREATE_FILE 2>&1
  fi
  if [ -f /etc/issue ]
  then
		echo "■ /etc/issue 확인(서버정보 출력여부 확인)" >> $CREATE_FILE 2>&1
		echo "☞ 서비스별 배너 경로 설정에 /etc/issue가 설정되어 있지 않으면 무관함 " >> $CREATE_FILE 2>&1
		cat /etc/issue >> $CREATE_FILE 2>&1
		echo "  " >> $CREATE_FILE 2>&1
  fi

  
  echo "■ 서버 로그온 시 출력 배너(/etc/motd) 확인" >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/motd ]
	then  
		if [ `cat /etc/motd | wc -l` -gt 0 ]
    	then
			 echo "GOOD" >> banner.fou
	   	 cat /etc/motd >> $CREATE_FILE 2>&1
		else
			echo
			echo "BAD" >> banner.fou 
		fi
  else
	  echo "☞ /etc/motd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	  echo "BAD" >> banner.fou
  fi
  
  echo "  " >> $CREATE_FILE 2>&1
  
  echo "■ SSH 관련 설정 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	  then
		  echo "☞ SSH 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	  else
		  echo "☞ SSH 서비스 활성화되어 있습니다." >> $CREATE_FILE 2>&1
		  echo "  " >> $CREATE_FILE 2>&1
          echo "■ ssh 배너 연동 여부" >> $CREATE_FILE 2>&1		  
		  cat ssh-banner.fou >> $CREATE_FILE 2>&1
		  
		  echo "  " >> $CREATE_FILE 2>&1
		  echo "■ 연동된 ssh 배너파일 존재시 해당 파일 내용" >> $CREATE_FILE 2>&1
		  
		  if [ `cat ssh-banner.fou | grep -v "^#" | wc -l` -gt 0 ]
		  then
			#170201
			ssh_path=`cat ssh-banner.fou | grep -v "^#" | awk -F' ' '{print $4}'`
			cat $ssh_path >> $CREATE_FILE 2>&1
			echo "GOOD" >> banner.fou
		  else
			echo "☞ ssh 배너 연동이 적절하지 않습니다." >> $CREATE_FILE 2>&1
			echo "BAD" >> banner.fou
		  fi
  fi
 
  ps -ef | grep telnetd  | grep -v grep >> banner_temp.fou
  
  if [ -f /etc/inetd.conf ]
  then
  cat /etc/inetd.conf | grep 'telnetd' | grep -v '#' >> banner_temp.fou
  fi
  
   echo "  " >> $CREATE_FILE 2>&1

  
  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | grep "telnet" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | grep telnet | awk '{print $9}'`
          do
            if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "☞ telnet 활성화되어 있습니다." >> telnetps.fou
            fi
          done
      fi
    else
      if [ -f /etc/inetd.conf ]
        then
          if [ `cat /etc/inetd.conf | grep -v '^ *#' | grep telnet | wc -l` -gt 0 ]
            then
              echo "☞ telnet 활성화되어 있습니다." >> telnetps.fou
          fi
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "■ Telnet 관련 설정 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
  ps -ef | grep telnetd  | grep -v grep >> telnetps.fou
  cat /etc/issue >> telnetbanner.fou
  cat /etc/issue.net >> telnetbanner.fou

  if [ `cat telnetps.fou | grep telnet | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ Telnet 서비스 활성화되어 있습니다." >> $CREATE_FILE 2>&1
      echo "■ TELNET 배너" >> $CREATE_FILE 2>&1
      if [ `cat telnetbanner.fou | egrep "Ubuntu|Kernel" | grep -v grep | wc -l` -eq 0 ]
        then
          echo "GOOD" >> banner.fou
          ls -al /etc/issue >> $CREATE_FILE 2>&1
          cat /etc/issue >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          ls -al /etc/issue.net >> $CREATE_FILE 2>&1
          cat /etc/issue.net >> $CREATE_FILE 2>&1
        else
          echo "BAD" >> banner.fou
          ls -al /etc/issue >> $CREATE_FILE 2>&1
          cat /etc/issue >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          ls -al /etc/issue.net >> $CREATE_FILE 2>&1
          cat /etc/issue.net >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.fou
      echo "☞ Telnet 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1
  echo "  " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | grep "ftp" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "☞ ftp 활성화되어 있습니다." >> ftpps.fou
                echo "■ /etc/xinetd.d/ FTP 구동 정보" >> $CREATE_FILE 2>&1
                ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" >> $CREATE_FILE 2>&1
                cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
            fi
          done
      fi
    else
      if [ -f /etc/inetd.conf ]
        then
          if [ `cat /etc/inetd.conf | grep -v '#' | grep ftp  | grep -v "tftp" |  wc -l` -gt 0  ]
            then
              echo "☞ ftp 활성화되어 있습니다." >> ftpps.fou
          fi
      fi
  fi

  ps -ef | grep ftp  | grep -v grep | grep -v "tftp" >> ftpps.fou
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpps.fou | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ FTP 서비스 활성화되어 있습니다" >> $CREATE_FILE 2>&1
      echo "■ FTP 배너" >> $CREATE_FILE 2>&1

      if [ -f /etc/welcome.msg ]
        then
          if [ `cat /etc/welcome.msg | grep -i "banner" | grep "=" | grep "\".\"" | wc -l` -eq 0 ]
            then
              echo "BAD" >> banner.fou
              cat /etc/welcome.msg >> $CREATE_FILE 2>&1
              echo " " >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.fou
              cat /etc/welcome.msg >> $CREATE_FILE 2>&1
              echo " " >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/vsftpd.conf ]
            then
              if [ `cat /etc/vsftpd.conf | grep -i "ftp_banner" | grep "=" | wc -l` -eq 0 ]
                then
                  echo "BAD" >> banner.fou
                  cat /etc/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
                else
                  echo "GOOD" >> banner.fou
                  cat /etc/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
              fi
            else
              if [ -f /etc/proftpd.conf ]
                then
                  if [ `cat /etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                    then
                      echo "BAD" >> banner.fou
                      cat /etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                    else
              	      echo "GOOD" >> banner.fou
                      cat /etc/proftpd.conf  | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                  fi
                else
                  if [ -f /usr/local/etc/proftpd.conf ]
                    then
                      if [ `cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                        then
                          echo "BAD" >> banner.fou
                          cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                        else
              	          echo "GOOD" >> banner.fou
              	          cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                      fi
                    else
                      if [ -f /etc/ftpaccess ]
                        then
                          if [ `cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" | wc -l` -eq 0 ]
                            then
                              echo "BAD" >> banner.fou
                              cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                            else
              	              echo "GOOD" >> banner.fou
                              cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                          fi
                        else
                          echo "미점검" >> banner.fou
                      fi
                  fi
              fi
          fi
      fi
    else
      echo "GOOD" >> banner.fou
      echo "☞ FTP 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi


  echo " " > banner_temp.fou
  echo "  " >> $CREATE_FILE 2>&1
  echo "■ SMTP 관련 설정 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ SMTP 서비스 활성화되어 있습니다." >> $CREATE_FILE 2>&1
      echo "■ SMTP 배너" >> $CREATE_FILE 2>&1
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" | grep -i "Sendmail" | wc -l` -gt 0 ]
            then
              echo "BAD" >> banner.fou
              echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.fou
              echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
          fi
        else
          echo "☞ 미점검" >> banner.fou
          echo "☞ /etc/mail/sendmail.cf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.fou
      echo "☞ SMTP 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi


  echo "  " >> $CREATE_FILE 2>&1
  echo "■ DNS 관련 설정 " >> $CREATE_FILE 2>&1
  echo "----------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ DNS 서비스 활성화되어 있습니다." >> $CREATE_FILE 2>&1
      echo "■ DNS 배너" >> $CREATE_FILE 2>&1
      if [ -f /etc/named.conf ]
        then
          if [ `cat /etc/named.conf | grep "version" | wc -l` -eq 0 ]
            then
              echo "BAD" >> banner.fou
              echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
              echo "☞ /etc/named.conf 파일 설정 없음" >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.fou
              echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/named.conf | grep -i "version" >> $CREATE_FILE 2>&1
          fi
        else
          echo "미점검" >> banner.fou
          echo "☞ /etc/named.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.fou
      echo "☞ DNS 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1

  if [ `cat banner.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-69. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-69. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi

  rm -rf ssh-banner.fou
  rm -rf banner.fou
  rm -rf banner_temp.fou
  rm -rf telnetbanner.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_70() {
  echo -n "U-70. NFS 설정파일 접근권한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-70. NFS 설정파일 접근권한 " >> $CREATE_FILE 2>&1
  echo ":: NFS 접근제어 설정파일의 소유자가 root이고, 권한이 644 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f  /etc/exports ]
    then
      ls -alL /etc/exports  >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/exports ]
    then
      if [ `ls -alL /etc/exports | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
        then
          echo "★ U-70. 결과 : 양호" >> $CREATE_FILE 2>&1
        else
          echo "★ U-70. 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-70. 결과 : 양호" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_71() {
  echo -n "U-71. expn, vrfy 명령어 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-71. expn, vrfy 명령어 제한 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo ":: 로컬(127.0.0.1)에서만 Sendmail 서비스를 사용할 경우 버전 및 설정에 관계없이 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "☞ Sendmail 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  
  echo "② SMTP 서비스 포트 활성화 여부 " >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
    if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -ge 1 ]
    then
	    smtpport=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;

	    if [ `netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ]
	      then
		      netstat -nat | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
			  echo "" >> $CREATE_FILE 2>&1
		      echo "☞ SMTP 서비스 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
			  echo "SMTPENABLE" >> smtpenable.fou 2>&1
		   
		   else
				if [ `netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "LISTEN" | wc -l` -ge 1 ]
				  then
					netstat -na | grep "127\.0\.0\.1\:$smtpport" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ 로컬에서 사용하는 SMTP 서비스의 포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou
				  else
					netstat -na | grep -w ":$smtpport " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
					echo "☞ SMTP 포트가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
					echo "SMTPDISABLE" >> smtpenable.fou 2>&1
				fi
		fi	
		
    else
	    if [ `netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -ge 1 ] 
		  then 
			netstat -nat | grep -w ":25 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1 
			echo "☞ SMTP 기본 포트가 활성화되어 있습니다.">> $CREATE_FILE 2>&1 
			echo "SMTPENABLE" > smtpenable.fou 2>&1 		   
		  else 
			if [ `netstat -na | grep "127\.0\.0\.1\:25" | grep -i "LISTEN" | wc -l` -ge 1 ]
			  then
				netstat -na | grep "127\.0\.0\.1\:25" | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
				echo "☞ 로컬에서 사용하는 SMTP 서비스의 기본포트가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			  else
				echo "☞ SMTP 기본 포트가 비활성화되어 있습니다.">> $CREATE_FILE 2>&1
				echo "SMTPDISABLE" >> smtpenable.fou
			fi
		fi 
   fi
  
   echo "" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
    else
      echo "☞ /etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-71. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" |grep -v "^#" |wc -l ` -eq 1 ]
            then
              echo "★ U-71. 결과 : 양호" >> $CREATE_FILE 2>&1
            else
              echo "★ U-71. 결과 : 취약" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-71. 결과 : 양호" >> $CREATE_FILE 2>&1
      fi
  fi

	rm -f smtpenable.fou 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


U_72() {
  echo -n "U-72. Apache 웹서비스 정보 숨김 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-72. Apache 웹서비스 정보 숨김 " >> $CREATE_FILE 2>&1
  echo ":: ServerTokens 지시자에 Prod 옵션이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  if [ $web = 'default' ]; then
	echo '☞ Apache 서비스 비활성화되어 있습니다.' >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "★ U-72. 결과 : N/A" >> $CREATE_FILE 2>&1
  else
		if [ $path = 'ok' ]; then
			cat $conf | grep ServerTokens | grep -v "^#" >> Tokens.txt
			if [ `awk 'BEGIN {IGNORECASE=1} /ServerTokens/ {print $0}' "$conf" | grep -v '\#'|wc -l` -gt 0 ]; then
				echo "| $apache/conf/httpd.conf |" >> $CREATE_FILE
				awk 'BEGIN {IGNORECASE=1} /ServerTokens/ {print $0}' "$conf" | grep -v '\#' >> $CREATE_FILE
				if [ `awk 'BEGIN {IGNORECASE=1} /ServerTokens/ && /Prod/ || /Off/ {print $0}' Tokens.txt | wc -l` -gt 0 ]; then
					result_72='Good'
				else
					result_72='Vulnerability'
				fi
			else
				if [ `cat "$conf" |grep Include | grep -v '\#'| grep httpd-default.conf | wc -l` -eq 1 ]
					then
					echo "| "$apache"/conf/httpd.conf |" >> $CREATE_FILE
					if [ `cat "$apache"/extra/httpd-default.conf | grep ServerTokens | grep -v '\#' | awk -F' ' '{print $2}'` = 'Prod' ]
						then 
						echo ' ' >> $CREATE_FILE
						echo "| "$apache"/conf/extra/httpd-default.conf |" >> $CREATE_FILE
						cat "$apache"/extra/httpd-default.conf | grep ServerTokens|grep -v '\#' >> $CREATE_FILE
						result_72='Good'
					else
						echo ' ' >> $CREATE_FILE
						echo "| "$apache"/conf/extra/httpd-default.conf |" >> $CREATE_FILE
						cat "$conf"/extra/httpd-default.conf | grep ServerTokens| grep -v '\#' >> $CREATE_FILE
						result_72='Vulnerability'
					fi
				else
					result_72='Vulnerability'
					echo "| "$apache"/conf/httpd.conf |" >> $CREATE_FILE
					if [ \( `cat "$conf" | grep Include | grep httpd-default.conf | grep -v '\#' | wc -l` -eq 0 \) -a \( `cat "$conf" | grep ServerTokens | grep -v '\#' | wc -l` -eq 0 \) ]; then
						echo '☞ 해당 설정이 존재하지 않음' >> $CREATE_FILE
					else
						if [ `cat "$conf" | grep Include | grep httpd-default.conf | grep -v '\#' | wc -l` -eq 0 ]; then
							cat "$conf" | grep ServerTokens >> $CREATE_FILE
						else
							cat "$conf" | grep Include | grep httpd-default.conf >> $CREATE_FILE
						fi
					fi
					echo ' ' >> $CREATE_FILE

					if [ ! -f "$apache"/extra/httpd-default.conf ]; then
						echo '☞ 해당 파일이 존재하지 않습니다.' >> $CREATE_FILE
					else
						cat "$apache"/extra/httpd-default.conf |grep ServerTokens >> $CREATE_FILE
					fi
				fi
			fi

		else
			result_72='interview'
			echo "ServerToken 설정 확인">> $CREATE_FILE 2>&1
			echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞ conf 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
		fi		
		
		if [ -f $apache/conf.d/userdir.conf ]
			then
			cat $apache/conf.d/userdir.conf | grep ServerTokens | grep -v "^#" >> Tokens.txt
			if [ `awk 'BEGIN {IGNORECASE=1} /ServerTokens/ {print $0}' "$apache/conf.d/userdir.conf" | grep -v '\#'|wc -l` -gt 0 ]; then
				echo "| $apache/conf.d/userdir.conf |" >> $OUTFILE
				awk 'BEGIN {IGNORECASE=1} /ServerTokens/ {print $0}' "$apache/conf.d/userdir.conf" | grep -v '\#' >> $OUTFILE
				if [ `awk 'BEGIN {IGNORECASE=1} /ServerTokens/ && /Prod/ || /Off/ {print $0}' Tokens.txt | wc -l` -gt 0 ]; then
					result_72='Good'
				else
					result_72='Vulnerability'
				fi
			else
				echo "ServerTokens 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
				echo "☞" $apache/conf.d/userdir.conf" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
			fi		
		fi
		
		rm -rf Tokens.txt
		
		if [ $result_72 = 'Vulnerability' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-72. 결과 : 취약" >> $CREATE_FILE 2>&1
		elif [ $result_72 = 'interview' ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-72. 결과 : 수동점검" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-72. 결과 : 양호" >> $CREATE_FILE 2>&1
		fi
		
	fi

  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_42() {
  echo -n "U-42. 최신 보안패치 및 벤더 권고사항 적용 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-42. 최신 보안패치 및 벤더 권고사항 적용 " >> $CREATE_FILE 2>&1
  echo ":: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "현재 UBUNTU 버전" >> $CREATE_FILE 2>&1
  echo "------------------------------------" >> $CREATE_FILE 2>&1
  uname -a >> $CREATE_FILE 2>&1
  
  echo " " >> $CREATE_FILE 2>&1
  
  echo "해당항목은 운영담당자와 인터뷰를 통해서 점검 진행" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "★ U-42. 결과 : 수동점검" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_43() {
  echo -n "U-43. 로그의 정기적 검토 및 보고 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-43. 로그의 정기적 검토 및 보고 " >> $CREATE_FILE 2>&1
  echo ":: 로그 기록의 검토, 분석, 리포트 작성 및 보고 등이 정기적으로 이루어지는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "해당항목은 운영담당자와 인터뷰를 통해서 점검 진행" >> $CREATE_FILE 2>&1
  echo "★ U-43. 결과 : 수동점검" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}

U_73() {
  echo -n "U-73. 정책에 따른 시스템 로깅 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-73. 정책에 따른 시스템 로깅 설정" >> $CREATE_FILE 2>&1
  echo ":: 로그 기록 정책이 정책에 따라 설정되어 수립되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ 시스템 현황" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  #20151113-01 
  #Start 
	if [ -f /etc/rsyslog.d/50-default.conf ]
		then	
			echo "① rsyslog 프로세스" >> $CREATE_FILE 2>&1
			echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
			ps -ef | grep 'rsyslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
		else
			echo "② syslog 프로세스" >> $CREATE_FILE 2>&1
			echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
			ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
	fi

  echo " " >> $CREATE_FILE 2>&1

  echo "③ 시스템 로깅 설정" >> $CREATE_FILE 2>&1
  echo "-----------------------------------------------" >> $CREATE_FILE 2>&1

	if [ -f /etc/rsyslog.d/50-default.conf ]
		then
			if [ `cat /etc/rsyslog.d/50-default.conf | wc -l` -gt 0 ]
				then 
					cat /etc/rsyslog.d/50-default.conf | grep -v "^#" | grep -v '^$' >> $CREATE_FILE 2>&1
				else
					echo "☞ /etc/rsyslog.d/50-default.conf  파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			fi
		elif [ -f /etc/rsyslog.d/50-default.conf ]
			then
				cat /etc/rsyslog.d/50-default.conf | grep -v "^#" | grep -v '^$' >> $CREATE_FILE 2>&1
			else	
				echo "☞ /etc/rsyslog.d/50-default.conf  파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		
	fi
	

  echo " " >> $CREATE_FILE 2>&1

  echo " " > syslog.fou
	if [ -f /etc/syslog.conf ] 
		then
			if [ `cat /etc/syslog.conf | egrep "info|alert|notice|debug" | egrep "var|log" | grep -v "^#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.fou
			else
				echo "BAD" >> syslog.fou
			fi
					
			if [ `cat /etc/syslog.conf | egrep "alert|err|crit" | egrep "console|sysmsg" | grep -v "^#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.fou
			else
				echo "BAD" >> syslog.fou
			fi

			if [ `cat /etc/syslog.conf | grep "emerg" | grep "\*" | grep -v "^#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.fou
			else 
				echo "BAD" >> syslog.fou
			fi
			
		elif [ -f /etc/rsyslog.d/50-default.conf ]
			then
				if [ `cat /etc/rsyslog.d/50-default.conf | egrep "info|alert|notice|debug" | egrep "var|log" | grep -v "^#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.fou
				else
					echo "BAD" >> syslog.fou
				fi
				if [ `cat /etc/rsyslog.d/50-default.conf | egrep "alert|err|crit" | egrep "console|sysmsg" | grep -v "^#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.fou
				else
					echo "BAD" >> syslog.fou
				fi
				if [ `cat /etc/rsyslog.d/50-default.conf | grep "emerg" | grep "\*" | grep -v "^#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.fou
				else
					echo "BAD" >> syslog.fou
				fi
									
		else
			echo "BAD" >> syslog.fou
	fi
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat syslog.fou | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-73. 결과 : 양호" >> $CREATE_FILE 2>&1
    else
      echo "★ U-73. 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
#end 

  rm -rf syslog.fou

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "완료"
  echo " "
}


#U1. 계정관리
U_01
U_02
U_03
U_04
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
#U2. 파일 및 디렉터리 관리
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
U_16
U_17
U_18
U_55
U_56
U_57
U_58
U_59
U_60
#U3. 서비스 관리
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_61
U_62
U_63
U_64
U_65
U_66
U_67
U_68
U_69
U_70
U_71
U_72
#U4. 패치 관리
U_42
#U5. 로그 관리
U_43
U_73

echo "#################################  IP 정보  ##################################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#################################  네트워크 현황 ###############################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "################################## 라우팅 정보 #################################" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "################################## 프로세스 현황 ###############################" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "################################## 사용자 환경 #################################" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "##################################  웹 정보  ##################################" >> $CREATE_FILE 2>&1
# 아파치 전문 출력
if [ $path = 'ok' ]; then
	ls $conf >> $CREATE_FILE 2>&1
	cat $conf >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "##################################  추가 파일 정보  ##################################" >> $CREATE_FILE 2>&1
echo '==========[ /etc/securetty 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/securetty >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/pam.d/common-auth  파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/pam.d/common-auth  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/pam.d/login 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/pam.d/login >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/passwd 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/group 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/shadow 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/shadow >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/profile 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/profile >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/csh.login =========='>> $CREATE_FILE 2>&1
cat /etc/csh.login >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/csh.cshrc =========='>> $CREATE_FILE 2>&1
cat /etc/csh.cshrc >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/hosts 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/hosts >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/inetd.conf =========='>> $CREATE_FILE 2>&1
cat /etc/inetd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/hosts.equiv 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/hosts.allow 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/hosts.allow >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/hosts.deny 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/hosts.deny >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/bashrc 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/bashrc >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/vsftpd.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/vsftpd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/vsftpd/vsftpd.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/vsftpd/vsftpd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/exports 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/exports >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/mail/sendmail.cf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/mail/sendmail.cf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/named.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/named.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/named.boot 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/named.boot >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/services 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/services >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/vsftpd.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/vsftpd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/proftpd.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/proftpd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/ftpd/ftpusers 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/ftpusers 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/ftpusers >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/vsftpd/user_list 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/issue.net 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/issue.net >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/issue 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/issue >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/motd 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/motd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/inetd.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/inetd.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/welcome.msg 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/welcome.msg >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/syslog.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/syslog.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/rsyslog.d/50-default.conf 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/rsyslog.d/50-default.conf >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo '==========[ /etc/ssh/sshd_config 파일 현황 ]==========' >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "☞ 점검작업이 완료되었습니다. 수고하셨습니다!"

# "***************************************  전체 결과물 파일 생성 시작  ***********************************"
 
_HOSTNAME=`hostname`
CREATE_FILE_RESULT=${_HOSTNAME}"__UBUNTU__"`date +%Y%m%d__%H%M`.txt
echo > $CREATE_FILE_RESULT

echo " "
cat $CREATE_FILE >> $CREATE_FILE_RESULT 2>&1
echo "***************************************  전체 결과물 파일 생성 끝 **************************************" #20150923-02

unset FILES
unset HOMEDIRS
unset SERVICE_INETD
unset SERVICE
unset APROC1
unset APROC
unset ACONF
unset AHOME
unset ACFILE
unset ServiceDIR
unset vsfile
unset profile
unset result

rm -Rf list.txt
rm -Rf result.txt
rm -Rf telnetps.fou ftpps.fou
rm -Rf vsftpd.fou
rm -Rf apa_Manual.txt
rm -Rf error.txt
rm -Rf pathinfo.txt

rm -Rf $CREATE_FILE 2>&1

