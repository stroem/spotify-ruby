require "rubygems"
require "ffi"
require "thread"

module Spotify
  extend FFI::Library

  ffi_lib "./libspotify.so"

  API_VERSION = 1
  LINK_TYPES = [:invalid, :track, :album, :artist, :search, :playlist]
  ERRORS = [
    :ok,                        # No errors encountered
          :bad_api_version,           # The library version targeted does not match the one you claim you support
          :api_initialization_failed, # Initialization of library failed - are cache locations etc. valid?
          :track_not_playable,        # The track specified for playing cannot be played
          :resource_not_loaded,       # One or several of the supplied resources is not yet loaded
          :bad_application_key,       # The application key is invalid
          :bad_username_or_password,  # Login failed because of bad username and/or password
          :user_banned,               # The specified username is banned
          :unable_to_contact_server,  # Cannot connect to the Spotify backend system
          :client_too_old,            # Client is too old, library will need to be updated
          :other_permament,           # Some other error occured, and it is permanent (e.g. trying to relogin will not help)
          :bad_user_agent,            # The user agent string is invalid or too long
          :missing_callback,          # No valid callback registered to handle events
          :invalid_indata,            # Input data was either missing or invalid
          :index_out_of_range,        # Index out of range
          :user_needs_premium,        # The specified user needs a premium account
          :other_transient,           # A transient error occured.
          :is_loading                 # The resource is currently loading
        ]

  attach_function :sp_album_artist,            [:pointer                  ], :pointer
  attach_function :sp_album_name,              [:pointer                  ], :string
  attach_function :sp_album_release,           [:pointer                  ], :void
  attach_function :sp_album_year,              [:pointer                  ], :int
  attach_function :sp_artist_name,             [:pointer                  ], :string
  attach_function :sp_artist_release,          [:pointer                  ], :void
  attach_function :sp_error_message,           [:int                      ], :string
  attach_function :sp_link_as_string,          [:pointer, :string, :int   ], :int
  attach_function :sp_link_as_track,           [:pointer                  ], :pointer
  attach_function :sp_link_create_from_string, [:string                   ], :pointer
  attach_function :sp_link_release,            [:pointer                  ], :void
  attach_function :sp_link_type,               [:pointer                  ], :int
  attach_function :sp_session_init,            [:pointer, :pointer        ], :int
  attach_function :sp_session_login,           [:pointer, :string, :string], :int
  attach_function :sp_session_process_events,  [:pointer, :pointer        ], :void
  attach_function :sp_session_user,            [:pointer                  ], :pointer
  attach_function :sp_track_album,             [:pointer                  ], :pointer
  attach_function :sp_track_artist,            [:pointer, :int            ], :pointer
  attach_function :sp_track_error,             [:pointer                  ], :int
  attach_function :sp_track_name,              [:pointer                  ], :string
  attach_function :sp_track_num_artists,       [:pointer                  ], :int
  attach_function :sp_track_release,           [:pointer                  ], :void
  attach_function :sp_user_canonical_name,     [:pointer                  ], :string
  attach_function :sp_user_display_name,       [:pointer                  ], :string
  attach_function :sp_user_is_loaded,          [:pointer                  ], :uchar


  class SessionConfig < FFI::Struct
    layout :api_version,          :int,
           :cache_location,       :pointer,
           :settings_location,    :pointer,
           :application_key,      :pointer,
           :application_key_size, :uint,
           :user_agent,           :pointer,
           :callbacks,            :pointer,
           :userdata,             :pointer
  end

  callback :connection_error,   [:pointer, :int                     ], :void
  callback :logged_in,          [:pointer, :int                     ], :void
  callback :logged_out,         [:pointer                           ], :void
  callback :log_message,        [:pointer, :string                  ], :void
  callback :message_to_user,    [:pointer, :string                  ], :void
  callback :metadata_updated,   [:pointer                           ], :void
  callback :music_delivery,     [:pointer, :pointer, :pointer, :int ], :int
  callback :notify_main_thread, [:pointer                           ], :void
  callback :play_token_lost,    [:pointer                           ], :void

  class SessionCallbacks < FFI::Struct
    layout :logged_in,          :logged_in,
           :logged_out,         :logged_out,
           :metadata_updated,   :metadata_updated,
           :connection_error,   :connection_error,
           :message_to_user,    :message_to_user,
           :notify_main_thread, :notify_main_thread,
           :music_delivery,     :music_delivery,
           :play_token_lost,    :play_token_lost,
           :log_message,        :log_message
  end

  class Client
    include Spotify

    class Error < StandardError; end

    attr_accessor :verbose, :key_file, :cache_location, :settings_location

    def initialize
      @verbose           = false
      @key_file          = nil
      @callbacks         = {}
      @cache_location    = File.dirname(__FILE__)
      @settings_location = File.dirname(__FILE__)

      yield self if block_given?
    end

    #
    # callbacks
    #

    [ :on_login,
      :on_logout,
      :on_metadata_updated,
      :on_connection_error,
      :on_message_to_user,
      :on_music_delivery,
      :on_lost_play_token,
      :on_log_message ].each do |meth|
        module_eval <<-RUBY
          def #{meth}(&blk)
            @callbacks[#{meth.inspect}] = blk
          end
        RUBY
    end

    #
    # login (needs premium user)
    #


    def login(user, pass)
      unless defined?(@session_ptr)
        create_config
        create_callbacks
        create_session
      end

      check_error sp_session_login(@session_ptr, user, pass)
    end

    #
    # logout
    #

    def logout
      check_error sp_session_logout(@session_ptr)
    end

    #
    # fetch info about the given uri
    #

    def info_for(uri)
      link_ptr = sp_link_create_from_string(uri)
      type = LINK_TYPES[sp_link_type(link_ptr)]

      raise "invalid uri" if type == :invalid || type.nil?
      info = { :type => type }
      case type
      when :track
        info.merge! track_info_for(link_ptr)
      else
        raise "unknown type #{type.inspect}"
      end

      sp_link_release(link_ptr)

      info
    end

    #
    # start the run loop
    #

    def run_loop
      sleep_ptr = FFI::MemoryPointer.new :int

      loop do
        sp_session_process_events(@session_ptr, sleep_ptr)
        sleep(sleep_ptr.read_int/1000)
      end
    end

    private

    def process_events
      sleep_ptr = FFI::MemoryPointer.new :int
      sp_session_process_events(@session_ptr, sleep_ptr)
      sleep(sleep_ptr.read_int/1000)
    end

    def create_config
      raise "must set Client#key_file=" unless @key_file
      key     = File.read(@key_file)
      @config = SessionConfig.new

      @config[:api_version]          = API_VERSION
      @config[:cache_location]       = FFI::MemoryPointer.from_string(@cache_location)
      @config[:settings_location]    = FFI::MemoryPointer.from_string(@settings_location)
      @config[:application_key]      = FFI::MemoryPointer.from_string(key)
      @config[:application_key_size] = key.size
      @config[:user_agent]           = FFI::MemoryPointer.from_string("Spotify Url Checker")
    end

    def create_callbacks
      log :creating_callbacks
      session_callbacks = SessionCallbacks.new

      session_callbacks[:logged_in]          = method(:logged_in).to_proc
      session_callbacks[:logged_out]         = method(:logged_out).to_proc
      session_callbacks[:metadata_updated]   = lambda { |*args| invoke_callback(:on_metadata_updated, *args) }
      session_callbacks[:connection_error]   = lambda { |*args| invoke_callback(:on_connection_error, *args) }
      session_callbacks[:message_to_user]    = lambda { |*args| invoke_callback(:on_message_to_user, *args) }
      session_callbacks[:notify_main_thread] = method(:notify_main_thread).to_proc
      session_callbacks[:music_delivery]     = lambda { |*args| invoke_callback(:on_music_delivery, *args) }
      session_callbacks[:play_token_lost]    = lambda { |*args| invoke_callback(:on_lost_play_token, *args) }
      session_callbacks[:log_message]        = lambda { |*args| invoke_callback(:on_log_message, *args) }

      @config[:callbacks] = session_callbacks.to_ptr
    end

    def create_session
      session_ptr_ptr = FFI::MemoryPointer.new(4)
      check_error sp_session_init(@config, session_ptr_ptr)

      @session_ptr = session_ptr_ptr.get_pointer(0)
    end

    def track_info_for(link_ptr)
      track_ptr = sp_link_as_track(link_ptr)
      raise TypeError, "not a track" if track_ptr.null?

      while (state = ERRORS[sp_track_error(track_ptr)]) == :is_loading
        p :state => state
        process_events
        sleep 0.5
      end

      info = {
        :album => {},
        :name => sp_track_name(track_ptr),
        :artists => []
      }

      artist_count = sp_track_num_artists(track_ptr)
      if artist_count > 0
        artist_ptrs = (0...artist_count).map { |idx| sp_track_artist(track_ptr, idx) }.reject { |ptr| ptr.null? }
        artist_ptrs.each do |ptr|
          info[:artists] << sp_artist_name(ptr)
          sp_artist_release(ptr)
        end
      end

      unless (album_ptr = sp_track_album(track_ptr)).null?
        unless (artist_ptr = sp_album_artist(album_ptr)).null?
          info[:album][:artist] = sp_artist_name(artist_ptr)
          sp_artist_release(artist_ptr)
        end

        info[:album][:name] = sp_album_name(album_ptr)
        info[:album][:year] = sp_album_year(album_ptr)

        sp_album_release(album_ptr)
      end

      sp_track_release(track_ptr)

      info
    end

    def logged_in(session, error)
      log :logged_in, session, error
      check_error error
      user_ptr = sp_session_user(session)
      log :logged_in_as, sp_user_is_loaded(user_ptr) != 0 ? sp_user_display_name(user_ptr) : sp_user_canonical_name(user_ptr)

      invoke_callback :on_login, session, error
    end

    def logged_out(session)
      log :logged_out, session

      invoke_callback :on_logout, session
    end

    def notify_main_thread(session)
      log :notify_main_thread, session
    end

    def check_error(error_code)
      if error_code != 0
        raise Error, sp_error_message(error_code)
      end
    end

    def log(*args)
      puts "#{self} @ #{Time.now} :: #{args.inspect}" if @verbose
    end

    def invoke_callback(key, *args)
      log key, *args
      cb = @callbacks[key]
      cb.call(*args) if cb
    end

  end # Client
end # Spotify

if __FILE__ == $0
  raise "USAGE: #{$0} <username> <password>" unless ARGV.size == 2

  user, pass = ARGV[0], ARGV[1]

  client          = Spotify::Client.new
  client.verbose  = true
  client.key_file = "spotify_appkey.key"

  client.on_login do
    p :info => client.info_for("spotify:track:1BjVDXkrSMlp4hyA1kxUQj")
  end

  client.login ARGV[0], ARGV[1]
  client.run_loop
end
