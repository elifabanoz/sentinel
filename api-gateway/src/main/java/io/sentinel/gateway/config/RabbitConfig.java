package io.sentinel.gateway.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
public class RabbitConfig {

    // Dead letter exchange 
    @Bean
    public DirectExchange deadLetterExchange() {
        return new DirectExchange("sentinel.dlx");
    }

    // Dead letter queue 
    @Bean
    public Queue deadLetterQueue() {
        return QueueBuilder.durable("sentinel.dlq").build();
    }

    @Bean
    public Binding deadLetterBinding() {
        return BindingBuilder.bind(deadLetterQueue()).to(deadLetterExchange()).with("dlq");
    }

    // Her scanner queue'su: durable + DLX 
    // x-dead-letter-exchange: 3 nack sonrası mesajı DLX'e gönder
    private Queue scanQueue(String name) {
        return QueueBuilder.durable(name)
                .withArgument("x-dead-letter-exchange", "sentinel.dlx")
                .withArgument("x-dead-letter-routing-key", "dlq")
                .build();
    }

    @Bean public Queue tlsQueue()   { return scanQueue("scan.tls"); }
    @Bean public Queue sqliQueue()  { return scanQueue("scan.sqli"); }
    @Bean public Queue xssQueue()   { return scanQueue("scan.xss"); }
    @Bean public Queue osintQueue() { return scanQueue("scan.osint"); }
    @Bean public Queue depsQueue()  { return scanQueue("scan.deps"); }

    // Map nesnesini JSON olarak serialize eder
    @Bean
    public Jackson2JsonMessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }
}
