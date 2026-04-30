package io.sentinel.gateway.config;

import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitConfig {

    @Bean public Queue tlsQueue()   { return new Queue("scan.tls",   true); }
    @Bean public Queue sqliQueue()  { return new Queue("scan.sqli",  true); }
    @Bean public Queue xssQueue()   { return new Queue("scan.xss",   true); }
    @Bean public Queue osintQueue() { return new Queue("scan.osint", true); }
    @Bean public Queue depsQueue()  { return new Queue("scan.deps",  true); }

    @Bean
    public Jackson2JsonMessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }
}
