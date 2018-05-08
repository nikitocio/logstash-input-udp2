# logstash-input-udp2
logstash input plugin for datadog logs through udp

#To install plugin in log stash
ADD ./logstash-input-udp2 /opt/logstash/logstash-input-udp2
RUN ${LOGSTASH_HOME}/bin/logstash-plugin install /opt/logstash/logstash-input-udp2/logstash-input-udp2-3.3.2.gem

#to declare plugin in config 
input {
    udp2 {
        port => 5044
    }
}

#open port for udp in config
5044/udp

