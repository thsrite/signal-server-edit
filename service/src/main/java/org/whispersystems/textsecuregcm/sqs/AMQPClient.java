package org.whispersystems.textsecuregcm.sqs;

import com.rabbitmq.client.BuiltinExchangeType;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.apache.commons.lang3.SerializationUtils;
import org.whispersystems.textsecuregcm.configuration.AMQPConfiguration;

import java.io.IOException;
import java.io.Serializable;
import java.util.concurrent.TimeoutException;

public class AMQPClient {
    private Channel channel;
    private Connection connection;
    private AMQPConfiguration amqpConfiguration;

    public AMQPClient(AMQPConfiguration amqpConfiguration) throws IOException, TimeoutException {
        this.amqpConfiguration = amqpConfiguration;
        initClient();
    }

    private void initClient() throws IOException, TimeoutException {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setConnectionTimeout(1000);
        factory.setUsername(amqpConfiguration.getUsername());
        factory.setPassword(amqpConfiguration.getPassword());
        factory.setHost(amqpConfiguration.getHost());
        factory.setPort(amqpConfiguration.getPort());

        connection = factory.newConnection();
        channel = connection.createChannel();
        channel.exchangeDeclare(amqpConfiguration.getExchange(), BuiltinExchangeType.DIRECT);
        channel.queueDeclare(amqpConfiguration.getQueue(), false, false, false, null);
        channel.queueBind(amqpConfiguration.getQueue(), amqpConfiguration.getExchange(), amqpConfiguration.getRoutingKey());
    }

    public void sendMessage(Serializable record) throws IOException {
        channel.basicPublish(amqpConfiguration.getExchange(), amqpConfiguration.getRoutingKey(), null, SerializationUtils.serialize(record));
    }

    public void close() throws IOException, TimeoutException {
        this.channel.close();
        this.connection.close();
    }
}
