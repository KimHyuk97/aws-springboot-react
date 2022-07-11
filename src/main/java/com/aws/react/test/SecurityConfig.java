package com.aws.react.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity // 얘를 활성화 하면 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다. -> 스프링 필터체인은 아래 SecurityConfig클래스를 말한다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)  
public class SecurityConfig extends WebSecurityConfigurerAdapter{


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    } 


    // 비밀번호 암호화
    @Bean
    BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    // 권한설정 하기
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();      // csrf 를 비활성화 한다는 의미 (csrf : post방싱ㄱ으로 값을 전송할 때 token을 사용해야하는 보안설정이다.)
		http
            .httpBasic().disable()
            .cors().configurationSource(corsConfigurationSource())
            .and()
                .authorizeRequests()    // 권한 설정을 하는 곳
                    .antMatchers("/admin/myadmin/**").hasAnyRole("SYSTEM","LOCAL")
                    .antMatchers("/admin/myadmin/list").hasRole("SYSTEM")
                    .anyRequest().permitAll()
            .and()
                .formLogin()
                .loginPage("/admin")
                .loginProcessingUrl("/admin/adminLoginProc")
                .usernameParameter("adminId")
				.passwordParameter("adminPwd")
                .defaultSuccessUrl("/admin/myadmin/member/list?mode=all")
                .failureUrl("/admin/login/failure")

            .and()
                .logout()
                    .logoutUrl("/admin/myadmin/logout")
                    .invalidateHttpSession(true)
                    .logoutSuccessUrl("/admin");


        // 중복 로그인 체크하기
        http.sessionManagement()
            .maximumSessions(1) // session 최대 허용 수      
            .maxSessionsPreventsLogin(false);   // false : 중복 로그인하면 이전 로그인이 풀린다.
    }
}
