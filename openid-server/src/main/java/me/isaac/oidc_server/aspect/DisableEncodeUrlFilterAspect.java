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
public class DisableEncodeUrlFilterAspect {
//    @Pointcut("execution(* org.springframework.web.filter.OncePerRequestFilter+.doFilterInternal(..)) " +
//            "&& target(org.springframework.security.web.session.DisableEncodeUrlFilter))")
    //@Pointcut("execution(* org.springframework.web..GenericFilterBean+.doFilter(..))")
    //@Pointcut("execution(* javax.servlet.Filter+.doFilter(..))  && !within(* && is(FinalType))")
    @Pointcut("execution(* org.springframework.security.web.session.DisableEncodeUrlFilter.doFilterInternal(..))")
    public void onDoFilter1() {
    }

    @Before("onDoFilter1()")
    public void doBefore(JoinPoint joinPoint) {
        log.info(">>> 拦截到 DisableEncodeUrlFilter.doFilter() 方法");
        //Method method =  ((MethodSignature) joinPoint.getSignature()).getMethod();

        ServletRequest req = (ServletRequest) joinPoint.getArgs()[0];
        if (req instanceof HttpServletRequest) {
            log.info("request uri=" + ((HttpServletRequest) req).getRequestURI());
        }
    }

    @Around("onDoFilter1()")
    public Object doAround(ProceedingJoinPoint joinPoint) throws Throwable {
        return joinPoint.proceed();
    }

    @After("onDoFilter1()")
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
        log.info("<<< 结束对 DisableEncodeUrlFilter.doFilter() 的拦截");
    }
}
