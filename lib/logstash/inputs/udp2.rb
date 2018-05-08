# encoding: utf-8
require "date"
require "logstash/inputs/base"
require "logstash/namespace"
require "socket"
require "stud/interval"
require "ipaddr"
require "json"

# Read messages as events over the network via udp. The only required
# configuration item is `port`, which specifies the udp port logstash
# will listen on for event streams.
#
class LogStash::Inputs::Udp2 < LogStash::Inputs::Base
  config_name "udp2"

    class Base
      def to_h
        instance_variables.map do |iv|
          value = instance_variable_get(:"#{iv}")
          [
            iv.to_s[1..-1], # name without leading `@`
            case value
            when Base then value.to_h # Base instance? convert deeply
            when Array # Array? convert elements
              value.map do |e|
                e.respond_to?(:to_h) ? e.to_h : e
              end
            else value # seems to be non-convertable, put as is
            end
          ]
        end.to_h
      end
    end

  default :codec, "plain"

  # The address which logstash will listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port which logstash will listen on. Remember that ports less
  # than 1024 (privileged ports) may require root or elevated privileges to use.
  config :port, :validate => :number, :required => true

  # The maximum packet size to read from the network
  config :buffer_size, :validate => :number, :default => 65536

  # The socket receive buffer size in bytes.
  # If option is not set, the operating system default is used.
  # The operating system will use the max allowed value if receive_buffer_bytes is larger than allowed.
  # Consult your operating system documentation if you need to increase this max allowed value.
  config :receive_buffer_bytes, :validate => :number

  # Number of threads processing packets
  config :workers, :validate => :number, :default => 2

  # This is the number of unprocessed UDP packets you can hold in memory
  # before packets will start dropping.
  config :queue_size, :validate => :number, :default => 2000

  HOST_FIELD = "host".freeze

  def initialize(params)
    super
    BasicSocket.do_not_reverse_lookup = true
  end

  def register
    @udp = nil
    @metric_errors = metric.namespace(:errors)
  end # def register

  def run(output_queue)
    @output_queue = output_queue

    begin
      # udp server
      udp_listener(output_queue)
    rescue => e
      @logger.warn("UDP listener died", :exception => e, :backtrace => e.backtrace)
      @metric_errors.increment(:listener)
      Stud.stoppable_sleep(5) { stop? }
      retry unless stop?
    end
  end

  def close
    if @udp && !@udp.closed?
      @udp.close rescue ignore_close_and_log($!)
    end
  end

  def stop
    if @udp && !@udp.closed?
      @udp.close rescue ignore_close_and_log($!)
    end
  end

  private

  def udp_listener(output_queue)
    @logger.info("Starting UDP listener", :address => "#{@host}:#{@port}")

    if @udp && !@udp.closed?
      @udp.close
    end

    if IPAddr.new(@host).ipv6?
      @udp = UDPSocket.new(Socket::AF_INET6)
    elsif IPAddr.new(@host).ipv4?
      @udp = UDPSocket.new(Socket::AF_INET)
    end
    # set socket receive buffer size if configured
    if @receive_buffer_bytes
      @udp.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, @receive_buffer_bytes)
    end
    rcvbuf = @udp.getsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF).unpack("i")[0]
    if @receive_buffer_bytes && rcvbuf != @receive_buffer_bytes
      @logger.warn("Unable to set receive_buffer_bytes to desired size. Requested #{@receive_buffer_bytes} but obtained #{rcvbuf} bytes.")
    end

    @udp.bind(@host, @port)
    @logger.info("UDP listener started", :address => "#{@host}:#{@port}", :receive_buffer_bytes => "#{rcvbuf}", :queue_size => "#{@queue_size}")

    @input_to_worker = SizedQueue.new(@queue_size)
    metric.gauge(:queue_size, @queue_size)
    metric.gauge(:workers, @workers)

    @input_workers = @workers.times do |i|
      @logger.debug("Starting UDP worker thread", :worker => i)
      Thread.new(i, @codec.clone) { |i, codec| inputworker(i, codec) }
    end

    while !stop?
      next if IO.select([@udp], [], [], 0.5).nil?
      # collect datagram messages and add to inputworker queue
      @queue_size.times do
        begin
          payload, client = @udp.recvfrom_nonblock(@buffer_size)
          break if payload.empty?
          @input_to_worker.push([payload, client])
        rescue IO::EAGAINWaitReadable
          break
        end
      end
    end
  ensure
    if @udp
      @udp.close_read rescue ignore_close_and_log($!)
      @udp.close_write rescue ignore_close_and_log($!)
    end
  end

  def inputworker(number, codec)
    LogStash::Util::set_thread_name("<udp.#{number}")

    begin
      while true
        payload, client = @input_to_worker.pop
        host = client[3]

        codec.decode(payload) { |event| push_decoded_event(host, event) }
        codec.flush { |event| push_decoded_event(host, event) }
      end
    rescue => e
      @logger.error("Exception in inputworker", "exception" => e, "backtrace" => e.backtrace)
      @metric_errors.increment(:worker)
    end
  end

  def push_decoded_event(host, event)
    decorate(event)

    $message = event.get("message")

    if !$message.is_a? String
      @output_queue.push(event)
      metric.increment(:events)
      return false
    end

    @result_event = Base.new
    event.set(HOST_FIELD, host) if event.get(HOST_FIELD).nil?
    @prAr = event.get("message").split("|")
    @part1Arr = @prAr[0].split(":")

    event.set("name", @part1Arr[0])
    event.set("value", @part1Arr[1])
    event.set("type", @prAr[1])

    if @prAr[2]
    @tags = @prAr[2].split(",");
    @i = 0;
    @event_tags_properties = Base.new
    #if @tags&&@tags.length>0
    #    while @i < @tags.length do

    #           @logger.info("logs for tag", "#{@tags}")
   #            @logger.info("Logs for i", "#{@i}")

    #           unless @tags[@i] || @tags.nil? || @tags.length == 0
   #                @nowItIsString = @tags[@i]
   #                if @nowItIsString
   #                    @splitedTag = @nowItIsString.split(":")
   #                        if @splitedTag.length > 0
   #                            @curKey = @splitedTag[0]
   #                            if @splitedTag[0] == "#statistic"
   #                                @curKey = 'statistic'
   #                            end
   #                            @splitedTag[0].gsub!(/[#]/, '')
   #                            @event_tags_properties.instance_variable_set("@#{@curKey}", "@#{@splitedTag[1]}")
   #                        end
   #                    end
   #                 end
   #        @i +=1
   #     end
   # end

    #@result_event.instance_variable_set("@tags", @event_tags_properties.to_h)
    end


    event.remove("message")



    @output_queue.push(event)
    metric.increment(:events)
  end

  def ignore_close_and_log(e)
    @logger.debug("ignoring close exception", "exception" => e)
  end
end
