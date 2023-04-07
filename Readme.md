**Centralized Secret Mangement**
- Provide fine-grained access to the secrets (only giving clients the bare minimum access to secrets they need to use
- You also want your secrets to be encrypted both at rest and in transit to the client.
- The ability to rotate secrets.
- Audit by whom and when scret was accessed.
- Root keys are changed regularly and are only stored in memory.
- Download and unzipped vault from https://www.vautlproject.io
- The folder where you unzip the vault, create vault.conf file.
**vault.conf**
backend "inmem"{
  va
}
listener "tcp"{
  address="0.0.0.0:8200"
  tls_disable = 1
}
disable_mlock = true

- listener specifies the endpoint that the clients can use to create a vault server. In this case , it will be the localhost on port 8200
- we disable the tls so that our location can connect to vault over http. In production, you want tls enabled
**Start Vault Server**
- vault server -config vault.config
- now open another terminal and set the vault address
- set VAULT_ADDR=http://localhost:8200
** Initialize vault**
- initialize vault with the vault operator init command.
- vault operator init 
 - vault returns five unsealed keys and a root token.
 - check the status of vault, you can see that it is sealed
  - vault status

- **Spring Vault**
 - It is an abstraction around vault by Hashicorp form the spring cloud project
 - <dependency-management>
 - <dependencies>
 - <dependency>
 - <groupId>org.springframework.cloud</groupId>
 - <artificatId>spring-cluod-vault-dependencies<artifactId>
 - <scope>import</scope>
 - <type>pom</type>
 - </dependency>
 - </dependencies>
 - </dependency-management>
 
 - <dependencies>
 - <dependency>
 - <groupId>org.springframework.cloud</groupId>
 - <artifactId>spring-cloud-starter-vault-config</artifactId>
 - </dependency>
 - </dependencies>
 
 **bootstrap.yml**
 - spring:
   - application:
    - name: crypto
   - cloud:
    - vault:
     - host: localhost
     - port: 8200
     - scheme: http
     - authentication: TOKEN
     - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX                 ${vault_token}}
 **application.yml**
 - server:
  - port: 8443
   - ssl:
    - key-store-password: password   ${keystore_password}
    - key-store: classpath:keystore.p12
    - key-store-type: PKCS12
    - key_alias: tomcat
    
** password argument Dvault_token On JVM startup**
- -Dvault_token=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 
 
