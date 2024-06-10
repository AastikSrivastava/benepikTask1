# benepikTask1
Build a backend system using Spring Boot for user authentication, authorization

// create config class for this ..

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig { 
  
    // User Creation 
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) { 
  
        // InMemoryUserDetailsManager 
        UserDetails admin = User.withUsername("Amiya") 
                .password(encoder.encode("123")) 
                .roles("ADMIN", "USER") 
                .build(); 
  
        UserDetails user = User.withUsername("Ejaz") 
                .password(encoder.encode("123")) 
                .roles("USER") 
                .build(); 
  
        return new InMemoryUserDetailsManager(admin, user); 
    } 
  
    // Configuring HttpSecurity 
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { 
        return http.csrf().disable() 
                .authorizeHttpRequests() 
                .requestMatchers("/auth/welcome").permitAll() 
                .and() 
                .authorizeHttpRequests().requestMatchers("/auth/user/**").authenticated() 
                .and() 
                .authorizeHttpRequests().requestMatchers("/auth/admin/**").authenticated() 
                .and().formLogin() 
                .and().build(); 
    } 
  
    // Password Encoding 
    @Bean
    public PasswordEncoder passwordEncoder() { 
        return new BCryptPasswordEncoder(); 
    } 
  
} 



//  create rest controller to test this 

@RestController
@RequestMapping("/order") 
public class UserController { 
  
    @GetMapping("/product") 
    public String welcome() { 
        return "Welcome this endpoint is not secure"; 
    } 
  
    @GetMapping("/user/product") 
    @PreAuthorize("hasAuthority('ROLE_USER')") 
    public String userProfile() { 
        return "Welcome to User Product"; 
    } 
  
    @GetMapping("/admin/product") 
    @PreAuthorize("hasAuthority('ROLE_ADMIN')") 
    public String adminProfile() { 
        return "Welcome to Admin Product"; 
    } 
  
} 


// now to test this , hit url http://localhost:8080/auth/user/product

After putting the correct Username and Password you can access your endpoint. Put this Username and Password

Username: Ejaz
Password: 123


// conecting database
spring.datasource.url=jdbc:postgresql://localhost:5432/order
spring.datasource.username=postgres
spring.datasource.password=20179003
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.properties.hibernate.format_sql=true

server.error.include-message=always

// adding dependency 


    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security.oauth.boot</groupId>
        <artifactId>spring-security-oauth2-autoconfigure</artifactId>
        <version>2.1.0.RELEASE</version>
    </dependency>


@Service
public class OrderService  {

   private final OrderRepository repository;

   public OrderService(OrderrRepository repository) {
       this.repository = repository;
   }

   @Override
   public OrderDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       Product product = repository.findByEmail(username).orElseThrow(() -> new RuntimeException("User not found: " + username));
       GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().name());
       return new Productdetails.Product(product.getEmail(), product.getPassword(), Arrays.asList(authority));
   }
}
    
@RestController
@RequestMapping("/api/users")
@Slf4j
@Validated
class UserController {

   private final UserRepository repository;

   private final PasswordEncoder passwordEncoder;

   UserController(UserRepository repository, PasswordEncoder passwordEncoder) {
       this.repository = repository;
       this.passwordEncoder = passwordEncoder;
   }



   @GetMapping
   Page<User> all(@PageableDefault(size = Integer.MAX_VALUE) Pageable pageable, OAuth2Authentication authentication) {
       String auth = (String) authentication.getUserAuthentication().getPrincipal();
       String role = authentication.getAuthorities().iterator().next().getAuthority();
       if (role.equals(User.Role.USER.name())) {
           return repository.findAllByEmail(auth, pageable);
       }
       return repository.findAll(pageable);
   }

   @GetMapping("/search")
   Page<User> search(@RequestParam String email, Pageable pageable, OAuth2Authentication authentication) {
       String auth = (String) authentication.getUserAuthentication().getPrincipal();
       String role = authentication.getAuthorities().iterator().next().getAuthority();
       if (role.equals(User.Role.USER.name())) {
           return repository.findAllByEmailContainsAndEmail(email, auth, pageable);
       }
       return repository.findByEmailContains(email, pageable);
   }

// creating utility class for Jwt

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${bezkoder.app.jwtSecret}")
  private String jwtSecret;

  @Value("${bezkoder.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {

    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername()))
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }
  
  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
               .parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
}
  

* create sign-in ,login apis

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(), 
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(), 
               signUpRequest.getEmail(),
               encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
} 
