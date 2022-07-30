package me.isaac.oidc_server.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Aspect
@Component
@Slf4j
public class UsernamePasswordAuthenticationFilterAspect {
    @Pointcut("execution(* org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter+.doFilter(..)) " +
            "&& target(org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter))")
    public void onDoFilter() {
    }

    @Before("onDoFilter()")
    public void doBefore(JoinPoint joinPoint) {
        log.info(">>> 拦截到 UsernamePasswordAuthenticationFilter.doFilter() 方法");
        //Method method =  ((MethodSignature) joinPoint.getSignature()).getMethod();

        ServletRequest req = (ServletRequest) joinPoint.getArgs()[0];
        if (req instanceof HttpServletRequest) {
            log.info("request uri=" + ((HttpServletRequest) req).getRequestURI());
        }
    }

    @Around("onDoFilter()")
    public Object doAround(ProceedingJoinPoint joinPoint) throws Throwable {
        return joinPoint.proceed();
    }

    @After("onDoFilter()")
    public void doAfter(JoinPoint joinPoint) {
        ServletResponse resp = (ServletResponse) joinPoint.getArgs()[1];
        if (resp instanceof HttpServletResponse) {
            log.info("输出Response");
            log.info("status=" + ((HttpServletResponse) resp).getStatus());
            log.info("headers=");
            for (String headerName : ((HttpServletResponse) resp).getHeaderNames()) {
                String headerValue = ((HttpServletResponse) resp).getHeader(headerName);
                log.info(headerName + " : " + headerValue);
            }
        }
        log.info("<<< 结束对 UsernamePasswordAuthenticationFilter.doFilter() 的拦截");
    }
}
