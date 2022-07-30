package me.isaac.oidc_server.aspect;

import lombok.extern.slf4j.Slf4j;
import me.isaac.oidc_server.common.LogIndent;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.Objects;

@Aspect
@Component
@Slf4j
public class ServerAspect {
    //    @Pointcut("execution(* org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter.*(..)) " +
//            "|| execution(* org.springframework.security.web.access.intercept.FilterSecurityInterceptor.*(..)) " +
//            "|| execution(* org.springframework.security.web.access.ExceptionTranslationFilter.*(..))")
    //@Pointcut("execution(* org.springframework.security.web..*.*(..)) && !within(* && is(FinalType))")
    @Pointcut("execution(* aaa..*.*(..))")
    public void webLog() {
    }

    @Before("webLog()")
    public void doBefore(JoinPoint joinPoint) {
        LogIndent.getInstance().addIndent();
        logInfo(">>> --------------------");
        logInfo("开始调用");
        logRequestInfo();
        logInfo(joinPointMessage(joinPoint));
    }

    /*异常通知*/
    @AfterThrowing(pointcut = "webLog()", throwing = "e")
    public void doAfterThrowing(JoinPoint joinPoint, Exception e) {
        logInfo("异常通知, 异常类: " + e.getClass() + " ,异常: " + e.getMessage());
    }

    /*最终通知*/
    @After("webLog()")
    public void doAfter(JoinPoint joinPoint) {
        logInfo("结束调用");
        //logInfo(joinPointMessage(joinPoint));
        logInfo("<<< --------------------");
        LogIndent.getInstance().minusIndent();
    }

    private void logRequestInfo() {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (!Objects.isNull(servletRequestAttributes)) {
            HttpServletRequest request = servletRequestAttributes.getRequest();
            logInfo("URL: " + request.getRequestURL().toString());
        }
    }

    private String joinPointMessage(JoinPoint joinPoint) {
        String targetClass = joinPoint.getTarget().getClass().getName();
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        String methodClass = method.getDeclaringClass().getName();

        return "调用方法: " + targetClass + "." + method.getName() + " 执行方法: " + methodClass + "." + method.getName();

//        logInfo("类: " + joinPoint.getTarget().getClass());
//
//        if (joinPoint.getSignature() instanceof MethodSignature) {
//            Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
//            logInfo("方法: " + method.getDeclaringClass() + "." + method.getName());
//        }
    }

    private void logInfo(String s) {
        String space = "";//开头的缩进
        for (int i = 0; i < LogIndent.getInstance().getIndent(); i++) {
            space = space + "   ";
        }
        log.info(space + s);
    }
}
