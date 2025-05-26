package Engine::Fuzzer {
    use strict;
    use warnings;
    use Try::Tiny;
    use Mojo::UserAgent;
    use URI::Escape;

    sub new {
        my ($class, $timeout, $headers, $skipssl, $proxy) = @_;

        $timeout //= 10;  
        $headers //= {};  
        die "Headers must be a hashref" unless ref $headers eq 'HASH';

        my $userAgent = Mojo::UserAgent->new()
            ->request_timeout($timeout)
            ->insecure($skipssl ? 1 : 0);

        if ($proxy) {
            $userAgent->proxy->http($proxy)->https($proxy);
        }

        return bless {
            useragent => $userAgent,
            headers   => $headers,
        }, $class;
    }

    my %FUZZ_FORMATS = (
        json      => sub { my ($payload, $value) = @_; $payload =~ s/\$\{FUZZ\}/$value/g; return $payload; },
        xml       => sub { my ($payload, $value) = @_; $payload =~ s/\$\{FUZZ\}/$value/g; return $payload; },
        multipart => sub { my ($payload, $value) = @_; $payload =~ s/\$\{FUZZ\}/$value/g; return $payload; },
        default   => sub { my ($payload, $value) = @_; $payload =~ s/\$\{FUZZ\}/uri_escape($value)/ge; return $payload; },
    );

    my %FUZZ_CONTEXTS = (
        query => sub {
            my ($self, $fuzz_value, $endpoint, $payload, $headers) = @_;
            return unless $endpoint =~ /\$\{FUZZ\}/;
            $endpoint =~ s/\$\{FUZZ\}/uri_escape($fuzz_value)/ge;
            return ($endpoint, $payload, $headers);
        },
        
        body => sub {
            my ($self, $fuzz_value, $endpoint, $payload, $headers, $format) = @_;
            return unless $payload && $payload =~ /\$\{FUZZ\}/;
            my $fuzzer = $FUZZ_FORMATS{$format} // $FUZZ_FORMATS{default};
            $payload = $fuzzer->($payload, $fuzz_value);
            return ($endpoint, $payload, $headers);
        },
        
        headers => sub {
            my ($self, $fuzz_value, $endpoint, $payload, $headers) = @_;
            my %fuzzed_headers = map {
                my $value = $self->{headers}->{$_};
                $value =~ s/\$\{FUZZ\}/$fuzz_value/g;
                ($_ => $value)
            } keys %{$self->{headers}};
            return ($endpoint, $payload, \%fuzzed_headers);
        },
    );

    sub transform_request {
        my ($self, $fuzz_value, $fuzz_context, $endpoint, $payload, $headers, $format) = @_;
        
        return ($endpoint, $payload, $headers) unless $fuzz_value && $fuzz_context;
        
        my $context_handler = $FUZZ_CONTEXTS{$fuzz_context};
        return ($endpoint, $payload, $headers) unless $context_handler;
        
        my ($new_endpoint, $new_payload, $new_headers) = 
            $context_handler->($self, $fuzz_value, $endpoint, $payload, $headers, $format);
        
        return (
            $new_endpoint // $endpoint,
            $new_payload // $payload, 
            $new_headers // $headers
        );
    }

    sub request {
        my ($self, $method, $agent, $endpoint, $payload, $accept, $fuzz_value, $fuzz_context, $format) = @_;

        return 0 unless $method && $endpoint;
        $fuzz_context //= '';
        $format //= 'default';

        my %base_headers = %{$self->{headers}};
        
        my ($fuzzed_endpoint, $fuzzed_payload, $fuzzed_headers) = 
            $self->transform_request($fuzz_value, $fuzz_context, $endpoint, $payload // '', \%base_headers, $format);

        my $request = $self->{useragent}->build_tx(
            $method => $fuzzed_endpoint => {
                'User-Agent' => $agent // 'Mojo::UserAgent',
                %{$fuzzed_headers},
                'Accept' => $accept // '*/*',
            } => $fuzzed_payload
        );

        try {
            my $response = $self->{useragent}->start($request)->result;

            return {
                Method      => $method,
                URL         => $fuzzed_endpoint,
                Code        => $response->code // 0,
                Response    => $response->message // '',
                Content     => $response->body // '',
                Length      => $response->headers->content_length // 0,
                FuzzValue   => $fuzz_value // '',
                FuzzContext => $fuzz_context,
            };
        }
        catch {
            return {
                Method      => $method,
                URL         => $fuzzed_endpoint,
                Code        => 0,
                Response    => "Request failed: $_",
                Content     => '',
                Length      => 0,
                FuzzValue   => $fuzz_value // '',
                FuzzContext => $fuzz_context,
            };
        };
    }
}

1;