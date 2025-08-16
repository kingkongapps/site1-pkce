mvn clean package

sshpass -p 'gksksla1$' scp -P 2222 target/site1-pkce-0.0.1-SNAPSHOT.jar hosu@www.kingkongapps.kr:/home/hosu/sso-test

sshpass -p 'gksksla1$' ssh -p 2222 hosu@www.kingkongapps.kr "/home/hosu/sso-test/restart-site1-pkce.sh"

