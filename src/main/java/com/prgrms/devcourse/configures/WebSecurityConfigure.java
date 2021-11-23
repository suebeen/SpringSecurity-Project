package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    //todo(미션1): 사용자 계정 추가
    // passwordEncoder는 NoOpPasswordEncoder로 사용함 (힌트: DelegatingPasswordEncoder)
    // 기본 로그인 계정을 AuthenticationManagerBuilder 클래스를 통해 추가

    //note: 해시 알고리즘을 사용해서 암호를 지정해야 한다. (error code: 500)
    // {noop} 을 붙여줘야 한다.
    // createSuccessAuthentication 안에서 upgradeEncoding : 패스워드 암호화
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin").password("{noop}admin123").roles("ADMIN");
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }

    // note: 스프링 시큐리티의 필터 설정하는 부분
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
                //note: 밑에 두줄은 작성안해도 무방
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()
                //note: 쿠키 기반의 자동로그인 (추후에 자세히)
                // AbstractAuthenticationProcessingFilter
                // RememberMeAuthenticationFilter
                .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
                .requiresChannel()
                .anyRequest().requiresSecure()
        ;
    }

}
