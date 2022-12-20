#/bin/sh

if [ -z $1 -o -z $2 ]
then
  echo "Incorrect usage."
  echo "./$0 <keystore name> <keystore pass>"
  exit 1
fi

CA_NAME=caroot
CA_KEYSIZE=4096
CA_KEYSTORE_PWD=123456

#
echo "------------------------------------------------------------------------"
echo "Establishment of the CA Root and CA Root Level Certificate"
echo "------------------------------------------------------------------------"

if [ -e $CA_NAME.jks ]
then
  echo "CA already exists."
else # generate certificate
  keytool -genkeypair -keyalg RSA -keysize $CA_KEYSIZE -alias ca -keystore $CA_NAME.jks -dname "CN=Root CA $CA_NAME" -storepass $CA_KEYSTORE_PWD -keypass $CA_KEYSTORE_PWD -ext bc=ca:true

  echo "CA generated a public-private pair, stored in keystore $CA_NAME.jks"
  echo "and a CA root certificate is stored in $CA_NAME.crt"
fi

keytool -export -alias ca -keystore $CA_NAME.jks -storepass $CA_KEYSTORE_PWD -file $CA_NAME.crt

echo "Root CA ESTABLISHED"
echo ""
echo "---------------------------------------------------------"
echo "The Root CA Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file $CA_NAME.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"

# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate

if [ -e $1.jks ]
then
  echo "Second level already exists. Rename or delete it before proceeding."
  echo "------------------------------------------------------------------------"
else

  echo "Now, we can import the CA root as a trusted certificate"
  echo "Let's store it in the $1.jks keystore"
  echo "------------------------------------------------------------------------"
  keytool -import -alias ca -file $CA_NAME.crt -keystore $1.jks -storepass $2 -keypass $2

  echo "------------------------------------------------------------------------"
  echo "Second Level Certificate"
  echo "------------------------------------------------------------------------"

  keytool -genkeypair -keyalg RSA -alias myKeys -keystore $1.jks -dname "CN=$1" -storepass $2 -keypass $2

  #  3) Next, a certificate request for the "CN=Leaf" certificate needs to be
  #  created.

  keytool -certreq -keystore $1.jks -storepass $2 -alias myKeys -file $1.csr

  #  4) Now creating the certificate with the certificate request generated
  #  above.

  keytool -gencert -keystore $CA_NAME.jks -storepass $CA_KEYSTORE_PWD -alias ca -infile $1.csr -outfile $1.crt
  keytool -import -alias myCert -file $1.crt -keystore $1.jks -storepass $2 -keypass $2

  #  5) And output certificate file will be created. Now let's see
  #  what its content is.

  keytool -printcert -file $1.crt

  echo "------------------------------------------------------------------------"
fi