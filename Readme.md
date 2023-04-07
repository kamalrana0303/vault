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
 
- **bootstrap.yml**
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


**dependencies**
- spring-boot-starter-mail

**application.yml**
- main:
  - host: smtp.gmail.com
  - port: 587
  - username: sdfsf@gmail.com
  - password: kdjfslf
  - properties:
   - mail:
    - smtp:
     - auth: true
     - starttls:
      - enable: true
  - protocol: smtp
  - test-connection: false
  
  Listen Event:
   - AutenticationFailureExpiredEvent
   - AuthenticationFailureServiceExceptionEvent
   - AuthenticationFailureLockedEvent
   - AuthenticationFailureCredentialsExpiredEvent
   - AuthenticationFailureDisabledEvent
   - AuthenticationFailureBadCredentialsEvent
   - AuthenticationFailureProviderNotFoundEvent
   
** Create a class extend ApplicationEvent**
 - ApplicationEvent -> UserRegisterationEvent(CryptoUser user)
 - EmailVerificationListener implements ApplicationListener<UserRegisterationEvent>
 - onApplicationEvent(UserRegisterationEvent event){
    String username = event.getUser().getUsername();
    String verificationId  = verificationService.createVerification(username);
    String email = event.getUser().getEmail();
    SimpleMailMessage message = new SimpleMailMessage();
    message.setSubject("Crypto Portfolio Account Verification");
    message.setText("Account activation link: https://localhost:8443/verify/email?id="+verificationId);
    message.setTo(email);
    mailSender.send(message);
 }
 
 - Verification(id,username)
 - UserDetailServiceNoSql implements UserDetailsService
  - private final UserRepository userRepository
  - UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
    CryptoUser user = userRepository.findByUsername(username);
    if(user == null){
      throw new UsernameNotFoundException(username);
    }
   /* return User.withUsername(user.getUsername()).password(user.getPassword()).roles("User").disabled(!user.isVerified()).build();*/
    MFAUser user = new MFAUser(user.getUsername(), user.getPassword(), user.isVerfied(), DEFAULT_ACC_NON_EXP, DEFAULT_CRED_NON_EXP, DEFAULT_ACC_NON_LOCKED, buildRoles(roles));
  user.setSecurityPin(user.getSecurityPin());
    return user;
  }
  class RegstrationController{
  @GetMapping("/register")
  public String register(Model model){
    model.addAttribute("user", new UserDto());
    return "register";
  }
  
  @PostMapping("/register")
  String register(@Valid @ModelAttribute("user") UserDto user, BindingResult result){
    if(result.hasErrors()){
      return "register";
    }
    CryptoUser cryptUser = new CryptoUser(user.getUsername(), user.getFirstname(), user.getLastname(), user.getEmail(), encoder.encode(user.getPassword()), encoder.encode(String.valueOf(user.getSecurityPin()), TOTP_ENABLED);
    repository.save(cryptUser);
    portfolioRepository.save(new Portfolio(user.getUsername(), new ArrayList<>()));
    eventPublisher.publishEvent(new UserRegisterationEvent(cryptUser));
    return "redirect:register?success";
  }
  }
  
  class VerificationController{
    @GetMapping("/verify/email")
    public String verifyEmail(@RequestParam String id){
      String username = verificationService.getUsernameForId(id);
      if(username !=null){
        CryptoUser user = userRepository.findByUsername(username);
        user.setVerified(true);
        userRepository.save(user);
      }
      return "redirect:/login-verified";
    }
  }
  
  
  class UsernamePasswordAuthenticationFilter{
    
  }
  
  class AdditionalAuthenticationdetails extends WebAuthenticationDetails{
    @Getter
    private String securityPin;
    
    public AdditionalAuthenticationDetails(HttpServletRequest request){
      super(request);
      String securityPin = request.getParameter("securityPin");
      if(securityPin != null){
        this.securityPin = securityPin;
      }
    }
    
  }
  
  class MFAUser extends User{
    private String securityPin;
  
    public MFAUser(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountnonLocked, Collection<? extends GrantedAuthority> auhtorities ){
  super(username,password,enabled,accountNonExpired,credentialsNonExpired,accountNonLocked,authorities);
}
  @Getter
  @Setter
  private String securityPin;
  }

  @Component
  public class AdditionalAuthenticationProvier extends DaoAuthenticationProvider{
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException{
  super.additionalAuthenticationChecks(userDetails,authentication);
  AdditionalAuthenticationDetails details = (AdditionalAuthenticationDetaills) authentication.getDetails();
  MFAUser user = (MFAUser) userDetails;
  if(!getPasswordEncoder().matches(details.getSecurityPin(),user.getSecurityPin())){
    throw new BadCredentialException("invalid security pin");
  }
  user.setSecurityPin(null);
}
  }
  
  
  SecurityConfigurationAdapter -> WebSecurityConfigurerAdapeter{
    @Autowired
    private AdditionAuthenticationProvider additionalProvider;
    @Autowired
    private TotpAuthenticationFilter totpAuthFilter;
    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandler;
  
    protected void configure(HttpSecurity http) throws Exception{
      http.addFilterBefore(totpAuthFilter, UsernamePasswordAuthenticationFilter.class).
      authorizeRequests().antMatchers("/register","/login", "/login-error", "/login-verified","/verifed")
    .antMatchers("/totp-login","/totp-login-error").hasAuthority(Authorities.TOTP_AUTH_AUTHORITY)
    .anyRequest().hasRole("USER").and()
    .formLogin().loginPage("/login")
    .successHandler(new AuthenticationSuccessHandlerImpl()).failureUrl("/login-error")
     .authenticationDetailsSource(new AdditionalAuthenticationDetailsSource());
    }
   }
  
  
 
 
