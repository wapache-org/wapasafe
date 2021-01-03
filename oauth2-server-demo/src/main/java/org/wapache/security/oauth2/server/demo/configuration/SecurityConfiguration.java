package org.wapache.security.oauth2.server.demo.configuration;

import org.wapache.security.oauth2.server.demo.security.SecurityUserDetails;
import org.wapache.security.oauth2.server.demo.security.SecurityUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

    /**
     * 用于计算密码.
     *
     * @param args
     */
    public static void main(String[] args) {

        // 原始密码
        String password = "admin";
        // hash次数 =  2^strength次, 取值范围[4,31]
        int strength = 4;

        // 解析参数
        if(args!=null){
            password = args.length>=1 ? args[0] : password;
            strength = args.length>=2 ? Integer.parseInt(args[1]) : strength;
        }

        // 加密算法
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(strength);
        // 先encode一次, 减少耗时误差
        encoder.encode(password);

        long n1 = System.nanoTime();
        // 加密密码
        String encoded = encoder.encode(password);
        long n2 = System.nanoTime();
        System.out.println(password+" => "+encoded);

        // 检查密码
        long n3 = System.nanoTime();
        boolean shouldBeTrue = encoder.matches(password, encoded);
        long n4 = System.nanoTime();
        boolean shouldBeFalse = encoder.matches(encoded, encoded);
        long n5 = System.nanoTime();
        System.out.println( password+
            " => should be true: "+ shouldBeTrue +
            " => should be false: "+ shouldBeFalse
        );
        System.out.println( "strength is "+strength+
            ", encode used:"+(n2-n1)+" ns" +
            ", match true password used: "+(n4-n3)+" ns" +
            ", match false password used: "+(n5-n4)+" ns"
        );

    }

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SecurityUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt格式
        // $2a$14$8P.uUqQYoB0.ivT.exavCemuBh.T4UqBI0zP233ziVAvzugVh9kaO
        // $2a: BCrypt版本号
        // $14: hash计算的反复回数 2^14=16384回
        // $8P.uUqQYoB0.ivT.exavCe: salt值(第7到29)
        // 其余部分: 密码的本体(第30到最后)
        return new BCryptPasswordEncoder(4);
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // 当把前端界面打包到spring-boot时, 需要这个配置, 如果只是用于api server, 则这个配置不需要.
        registry.addViewController("/").setViewName("forward:/index.html");
        registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests().antMatchers("/", "/index.html",
            "/webjars/**",
            "/swagger-resources/**",
            "/swagger-ui.html**",
            "/v3/api-docs",
            "/docs/**",

            "/component/**",
            "/css/**",
            "/fonts/**",
            "/images/**",
            "/img/**",
            "/js/**",

            "/mock/**",
            "/authorize",
            "/authorize/*",
            "/accessToken",
            "/accessToken/*",
            "/resource"
        ).permitAll() // 不需要登录的URL
        .anyRequest().authenticated(); // 其他的需要登录

        http.formLogin()
            .loginProcessingUrl("/login").loginPage("/login.html")
            .usernameParameter("username").passwordParameter("password")
            //登录成功，返回json
            .successHandler((request,response,authentication) -> {
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json;charset=utf-8");
                PrintWriter out = response.getWriter();

                UserDetails userDetail = (UserDetails)authentication.getPrincipal();
                SecurityUserDetails sysUserEntity = userDetailsService.loadUserByUsername(userDetail.getUsername());

                out.write("{\"code\":0,\"message\":\"登录成功\",\"id\":"+sysUserEntity.getUser().getId()+", \"name\":\""+sysUserEntity.getUsername()+"\"}");
                out.flush();
                out.close();
            })
            //登录失败，返回json
            .failureHandler((request,response,ex) -> {
                response.setContentType("application/json;charset=utf-8");
//                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setStatus(HttpServletResponse.SC_OK);
                PrintWriter out = response.getWriter();
                Map<String,Object> map = new HashMap<String,Object>();
                map.put("code",-1);
                if (ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                    map.put("message","用户名或密码错误");
                } else if (ex instanceof DisabledException) {
                    map.put("message","账户被禁用");
                } else {
                    map.put("message","登录失败!");
                }
                out.write(objectMapper.writeValueAsString(map));
                out.flush();
                out.close();
            })
            .permitAll()
            .and()
            // TODO 不能加这一段, 加了前面的免登录的url全部无法工作.
//        .sessionManagement().invalidSessionStrategy((request, response)->{
//            response.setContentType("application/json;charset=utf-8");
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            PrintWriter out = response.getWriter();
//            Map<String,Object> map = new HashMap<String,Object>();
//            map.put("code",-2);
//            map.put("message","登录已超时, 请重新登录");
//            out.write(objectMapper.writeValueAsString(map));
//            out.flush();
//            out.close();
//        })
//        .and()
            .exceptionHandling()
            // 没有登录时, 防止重定向
//            .authenticationEntryPoint((request,response,ex) -> {
//                response.setContentType("application/json;charset=utf-8");
//                PrintWriter out = response.getWriter();
//                Map<String,Object> map = new HashMap<String,Object>();
//                map.put("code",-3);
//                map.put("message", "登录已超时, 请重新登录");
//                out.write(objectMapper.writeValueAsString(map));
//                out.flush();
//                out.close();
//            })
            // 没有权限，返回json
            .accessDeniedHandler((request,response,ex) -> {
                ex.printStackTrace();
                response.setContentType("application/json;charset=utf-8");
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                PrintWriter out = response.getWriter();
                Map<String,Object> map = new HashMap<String,Object>();
                map.put("code",-4);
                map.put("message", "没有权限执行此操作");
                out.write(objectMapper.writeValueAsString(map));
                out.flush();
                out.close();
            })
            .and()
            .logout().logoutUrl("/logout")
            //退出成功，返回json
            .logoutSuccessHandler((request,response,authentication) -> {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter out = response.getWriter();
                out.write("{\"code\":0,\"message\":\"退出系统成功\"}");
                out.flush();
                out.close();
            }).permitAll();

        http.headers().frameOptions().disable();
        http.cors().disable();
        http.csrf().disable();

    }

}
