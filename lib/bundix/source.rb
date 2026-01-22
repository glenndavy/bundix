class Bundix
  class Fetcher
    attr_accessor :vendor_path

    def sh(*args, &block)
      Bundix.sh(*args, &block)
    end

    def download(file, url, limit = 10)
      warn "Downloading #{file} from #{url}"
      uri = URI(url)

      case uri.scheme
      when nil # local file path
        FileUtils.cp(url, file)
      when 'http', 'https'
        unless uri.user
          inject_credentials_from_bundler_settings(uri)
        end

        Net::HTTP.start(uri.host, uri.port, use_ssl: (uri.scheme == 'https')) do |http|
          request = Net::HTTP::Get.new(uri)
          if uri.user
            request.basic_auth(uri.user, uri.password)
          end

          http.request(request) do |resp|
            case resp
            when Net::HTTPOK
              File.open(file, 'wb+') do |local|
                resp.read_body { |chunk| local.write(chunk) }
              end
            when Net::HTTPRedirection
              location = resp['location']
              raise "http error: Redirection loop detected" if location == url
              raise "http error: Too many redirects" if limit < 1

              warn "Redirected to #{location}"
              download(file, location, limit - 1)
            when Net::HTTPUnauthorized, Net::HTTPForbidden
              debrief_access_denied(uri.host)
              raise "http error #{resp.code}: #{uri.host}"
            else
              raise "http error #{resp.code}: #{uri.host}"
            end
          end
        end
      else
        raise "Unsupported URL scheme"
      end
    end

    def inject_credentials_from_bundler_settings(uri)
      @bundler_settings ||= Bundler::Settings.new(Bundler.root + '.bundle')

      if val = @bundler_settings[uri.host]
        uri.user, uri.password = val.split(':', 2)
      end
    end

    def debrief_access_denied(host)
      print_error(
        "Authentication is required for #{host}.\n" +
        "Please supply credentials for this source. You can do this by running:\n" +
        " bundle config packages.shopify.io username:password"
      )
    end

    def print_error(msg)
      msg = "\x1b[31m#{msg}\x1b[0m" if $stdout.tty?
      STDERR.puts(msg)
    end

    # Use nix-prefetch-url directly on URL, bypassing Ruby Net::HTTP entirely
    # This avoids IPv6 issues and network fragility
    def nix_prefetch_url_direct(url)
      warn "Prefetching #{url} directly with nix-prefetch-url" if $VERBOSE
      result = sh(
        Bundix::NIX_PREFETCH_URL,
        '--type', 'sha256',
        '--name', File.basename(url),
        url  # Direct URL, not file://
      ).force_encoding('UTF-8').strip
      result
    rescue => ex
      STDERR.puts("nix-prefetch-url failed for #{url}: #{ex.message}")
      STDERR.puts(ex.full_message) if $VERBOSE
      nil
    end

    def nix_prefetch_url(url)
      dir = File.join(ENV['XDG_CACHE_HOME'] || "#{ENV['HOME']}/.cache", 'bundix')
      FileUtils.mkdir_p dir
      file = File.join(dir, url.gsub(/[^\w-]+/, '_'))

      download(file, url) unless File.size?(file)
      return unless File.size?(file)

      sh(
        Bundix::NIX_PREFETCH_URL,
        '--type', 'sha256',
        '--name', File.basename(url), # --name mygem-1.2.3.gem
        "file://#{file}",             # file:///.../https_rubygems_org_gems_mygem-1_2_3_gem
      ).force_encoding('UTF-8').strip
    rescue => ex
      STDERR.puts(ex.full_message)
      nil
    end

    def nix_prefetch_git(uri, revision, submodules: false)
      home = ENV['HOME']
      ENV['HOME'] = '/homeless-shelter'

      args = []
      args << '--url' << uri
      args << '--rev' << revision
      args << '--hash' << 'sha256'
      args << '--fetch-submodules' if submodules

      sh(NIX_PREFETCH_GIT, *args)
    ensure
      ENV['HOME'] = home
    end

    def format_hash(hash)
      sh(NIX_HASH, '--type', 'sha256', '--to-base32', hash)[SHA256_32]
    end

    def fetch_local_hash(spec)
      spec.source.caches.each do |cache|
        path = File.join(cache, "#{spec.full_name}.gem")
        next unless File.file?(path)
        hash = nix_prefetch_url(path)&.[](SHA256_32)
        return format_hash(hash) if hash
      end

      nil
    end

    # Compute sha256 from vendor path file if it exists
    def fetch_vendor_hash(spec)
      return nil unless vendor_path

      gem_file = "#{spec.full_name}.gem"
      vendor_gem_path = File.join(vendor_path, gem_file)

      return nil unless File.file?(vendor_gem_path)

      warn "Using #{gem_file} from vendor path for hash" if $VERBOSE
      hash = nix_prefetch_url(vendor_gem_path)&.[](SHA256_32)
      return format_hash(hash) if hash

      nil
    end

    # Detect current platform and try platform-specific gem first
    def detect_platform
      case RUBY_PLATFORM
      when /x86_64-linux/ then 'x86_64-linux'
      when /aarch64-linux/ then 'aarch64-linux'
      when /arm64-darwin|aarch64-darwin/ then 'arm64-darwin'
      when /x86_64-darwin/ then 'x86_64-darwin'
      else 'ruby' # fallback to ruby platform
      end
    end

    # Try platform-specific gem, fall back to ruby platform
    def fetch_remote_hash_smart(spec, remote)
      use_direct = ENV['BUNDIX_USE_DIRECT_PREFETCH'] == '1'
      platform = ENV['BUNDIX_TARGET_PLATFORM'] || detect_platform

      # Try platform-specific gem first (precompiled)
      if platform != 'ruby'
        platform_uri = "#{remote}/gems/#{spec.name}-#{spec.version}-#{platform}.gem"
        warn "Trying platform-specific: #{platform_uri}" if $VERBOSE

        hash = use_direct ? nix_prefetch_url_direct(platform_uri) : nix_prefetch_url(platform_uri)
        if hash && hash[SHA256_32]
          puts "Using #{platform} platform gem for #{spec.name}" if $VERBOSE
          return hash[SHA256_32]
        end
      end

      # Fall back to ruby platform (needs compilation)
      warn "Falling back to ruby platform for #{spec.name}" if $VERBOSE
      uri = "#{remote}/gems/#{spec.full_name}.gem"
      result = use_direct ? nix_prefetch_url_direct(uri) : nix_prefetch_url(uri)
      result&.[](SHA256_32)
    rescue => e
      puts "Error fetching #{spec.name}: #{e.message}" if $VERBOSE
      nil
    end

    def fetch_remotes_hash(spec, remotes)
      remotes.each do |remote|
        hash = fetch_remote_hash(spec, remote)
        return remote, format_hash(hash) if hash
      end

      nil
    end

    def fetch_remote_hash(spec, remote)
      # Use smart platform-aware fetching
      fetch_remote_hash_smart(spec, remote)
    rescue => e
      puts "ignoring error during fetching: #{e}"
      puts e.backtrace if $VERBOSE
      nil
    end
  end

  class Source < Struct.new(:spec, :fetcher)
    def convert
      case spec.source
      when Bundler::Source::Rubygems
        convert_rubygems
      when Bundler::Source::Git
        convert_git
      when Bundler::Source::Path
        convert_path
      else
        pp spec
        fail 'unknown bundler source'
      end
    end

    def convert_path
      {
        type: "path",
        path: spec.source.path
      }
    end

    def convert_rubygems
      remotes = spec.source.remotes.map{|remote| remote.to_s.sub(/\/+$/, '') }

      # Prefer vendor path hash if available, then local cache, then remote
      hash = fetcher.fetch_vendor_hash(spec)
      hash ||= fetcher.fetch_local_hash(spec)
      remote, hash = fetcher.fetch_remotes_hash(spec, remotes) unless hash
      fail "couldn't fetch hash for #{spec.full_name}" unless hash
      puts "#{hash} => #{spec.full_name}.gem" if $VERBOSE

      { type: 'gem',
        remotes: (remote ? [remote] : remotes),
        sha256: hash }
    end

    def convert_git
      revision = spec.source.options.fetch('revision')
      uri = spec.source.options.fetch('uri')
      submodules = !!spec.source.submodules

      # Check if gem is available in vendor/cache as a directory (from bundle package --all)
      # Format: vendor/cache/gemname-shortrev (e.g., opscare-reports-87e403c81899)
      # Note: gem names may use underscores but git repos use hyphens, so try both
      short_rev = revision[0..11]  # First 12 chars of git revision

      # Try with original gem name (e.g., opscare_reports)
      vendor_dir = File.join(Dir.pwd, 'vendor', 'cache', "#{spec.name}-#{short_rev}")
      # Try with hyphens instead of underscores (e.g., opscare-reports)
      vendor_dir_hyphen = File.join(Dir.pwd, 'vendor', 'cache', "#{spec.name.tr('_', '-')}-#{short_rev}")

      if File.directory?(vendor_dir)
        warn "Using local path for #{spec.name} from #{vendor_dir}" if $VERBOSE
        return {
          type: "path",
          path: "./vendor/cache/#{spec.name}-#{short_rev}"
        }
      elsif File.directory?(vendor_dir_hyphen)
        warn "Using local path for #{spec.name} from #{vendor_dir_hyphen}" if $VERBOSE
        return {
          type: "path",
          path: "./vendor/cache/#{spec.name.tr('_', '-')}-#{short_rev}"
        }
      end

      # Fall back to git fetching if not in vendor/cache
      output = fetcher.nix_prefetch_git(uri, revision, submodules: submodules)
      # FIXME: this is a hack, we should separate $stdout/$stderr in the sh call
      hash = JSON.parse(output[/({[^}]+})\s*\z/m])['sha256']
      fail "couldn't fetch hash for #{spec.full_name}" unless hash
      puts "#{hash} => #{uri}" if $VERBOSE

      { type: 'git',
        url: uri.to_s,
        rev: revision,
        sha256: hash,
        fetchSubmodules: submodules }
    end
  end
end
