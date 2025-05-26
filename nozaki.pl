#!/usr/bin/env perl

use 5.030;
use strict;
use threads;
use warnings;
use Thread::Queue;
use Find::Lib "./lib";
use Functions::Helper;
use Functions::Parser;
use Engine::Orchestrator;
use Getopt::Long qw(:config no_ignore_case);

sub main {
    my ($workflow, @targets);

    my %options = (
        accept   => "*/*",
        wordlist => "wordlists/default.txt",
        method   => "GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH,PUSH",
        headers  => {},
        timeout  => 10,
        agent    => "Nozaki / 0.3.0",
        tasks    => 30,
        delay    => 0,
        fuzz     => "",
        format   => "urlencoded",
        data     => ""
    );

    Getopt::Long::GetOptions (
        "A|accept=s"       => \$options{accept},
        "a|agent=s"        => \$options{agent},
        "c|content=s"      => \$options{content},
        "d|delay=i"        => \$options{delay},
        "e|exclude=s"      => \$options{exclude},
        "H|header=s"       => sub { my ($opt, $value) = @_; my ($k, $v) = split(/:/, $value, 2); $options{headers}->{$k} = $v ? $v : ""; },
        "w|wordlist=s"     => \$options{wordlist},
        "W|workflow=s"     => \$workflow,
        "m|method=s"       => \$options{method},
        "r|return=s"       => \$options{return},
        "p|payload=s"      => \$options{payload},
        "j|json"           => \$options{json},
        "S|skip-ssl"       => \$options{skipssl},
        "T|tasks=i"        => \$options{tasks},
        "t|timeout=i"      => \$options{timeout},
        "u|url=s@"         => \@targets,
        "l|length=s"       => \$options{length},
        "P|proxy=s"        => \$options{proxy},
        "report-to=s"      => \$options{report_to},
        "report-format=s"  => \$options{report_format},
        "fuzz=s"           => \$options{fuzz},
        "format=s"         => \$options{format},
        "data=s"           => \$options{data}  
    );

    return Functions::Helper->new() unless @targets;

    if ($workflow) {
        my $rules = Functions::Parser->new($workflow);

        for my $rule (@$rules) {
            my %new_options = %options;

            Engine::Orchestrator::add_target(@targets);

            map { $new_options{$_} = $rule->{$_} || 1 } keys %{$rule};

            Engine::Orchestrator->run_fuzzer(%new_options);
        }

        return 0;
    }

    Engine::Orchestrator::add_target(@targets);

    return Engine::Orchestrator->run_fuzzer(%options);
}

exit main() unless caller;