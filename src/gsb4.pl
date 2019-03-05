#!/usr/bin/perl

use warnings FATAL => 'all';
use strict;
use Log::Log4perl qw(:easy);
use Net::Google::SafeBrowsing4;
use Net::Google::SafeBrowsing4::Storage::File;
use IO::Compress::Gzip qw(gzip $GzipError);
# use JSON -convert_blessed_universally;
use Storable qw(nstore retrieve);
use File::Copy qw(move);
use File::Path qw(mkpath rmtree);
use lib '.';
use Gsb4::Utils;             # for loading options/configs from main.yaml
use Gsb4::Lockf;             # for synchronize processes
use Digest::MD5;             # for compute checksum
use JSON::Streaming::Writer; # for write big json files
use MIME::Base64;            # for encode base64;

Log::Log4perl->easy_init($DEBUG);

my $LOGGER = Log::Log4perl->get_logger();
# json with pretty output
# my $json = JSON->new->utf8->pretty(0);

sub main {
    my $opts = get_config();
    my $LOCK = lockf($opts->{lock_file}, { blocking => 0 });
    unless (defined $LOCK) {
        $LOGGER->info("Already locked. Terminating...");
        exit(0);
    }

    # create $opts->{storage} if not exist
    unless (-d $opts->{storage}) {
        mkpath($opts->{storage}) or die "Cannot create $opts->{storage}: $!";
    }

    # create gsb object:
    my $storage = Net::Google::SafeBrowsing4::Storage::File->new(
        path   => $opts->{storage},
        logger => $LOGGER,
    );
    my $gsb = Net::Google::SafeBrowsing4->new(
        key     => $opts->{api_key},
        storage => $storage,
        logger  => $LOGGER,
    );
    # update
    $gsb->update();
    # close storage
    $storage->close();

    my $lists = $storage->get_lists();
    $LOGGER->info("Number of threat-list in lists.gsb4 file: ", scalar(@{$lists}));
    my $current_data_version = $storage->last_update();

    my $DATA_DIR = $opts->{storage};
    my $EXTRACT_DIR = $opts->{output};

    my $current_extracted_version = get_last_update_in_extract_dir($EXTRACT_DIR);
    if ($current_extracted_version < $current_data_version->{last_update} && $current_data_version->{errors} == 0) {
        $LOGGER->info("Start extraction since there is newer version");
        # create temp folder for extraction
        my $TEMP_DIR = make_tmp_dir();

        # make sure extract dir exists
        if (!-d $EXTRACT_DIR) {
            mkpath($EXTRACT_DIR, 0, 0777) or die("Cannot create directory " . $EXTRACT_DIR . ": $!\n");
        }

        # start extract input files to readable (for human & java) .gz files
        my $tmp_json_output = "$TEMP_DIR/db.json";
        open my $fh, '>', $tmp_json_output or die "Cannot open file to write $!";
        my $json_writer = JSON::Streaming::Writer->for_stream($fh);
        $json_writer->pretty_output(1);
        $json_writer->start_array();
        $LOGGER->info("Extraction to tmp - begins");
        foreach my $list (@{$lists}) {
            my $threat_name = list_to_file($list);
            my $input_data_file = $DATA_DIR . "/" . $threat_name;
            $json_writer->start_object();
            $json_writer->add_property("listType", $list);
            load_single_data_file_and_write_to_json_stream($input_data_file, $json_writer);
            $json_writer->end_object();
        }
        $json_writer->end_array();
        close $fh;

        write_last_update_file($TEMP_DIR, $current_data_version->{last_update});

        $LOGGER->info("Extraction to tmp - ends");

        write_checksum_file($tmp_json_output);

        # move all files in tmp folder to real folder, note that old extracted files might still be there
        $LOGGER->info("Move tmp to real output folder");
        move_tmp_to_real($TEMP_DIR, $EXTRACT_DIR);
        rmdir($TEMP_DIR) || die "Couldn't remove $TEMP_DIR. Error:$!";
    }
    else {
        $LOGGER->info("Skip extraction since it's up-to-date");
    }
    $LOGGER->info("Done");
    undef($LOCK);
}

sub write_last_update_file {
    my $file_path = "$_[0]/last_update";
    open my $fh, '>', "$file_path" or die "Cannot open file [$file_path] to write $!";
    print $fh $_[1];
    close $fh;
}

sub load_single_data_file_and_write_to_json_stream {
    my ($data_file, $json_writer) = @_;
    my $data = retrieve($data_file);
    my @raw_array = @{$data->{hashes}};
    my $raw_hash = '';
    my $size = scalar(@raw_array);
    $LOGGER->debug("Processing [$data_file] - $size hashes");
    for my $hash (@raw_array) {
        last if length($hash) != 4; # if the raw_array have only 1 element and the element's length is not 4 then the element is actually the state; we don't want to write it
        $raw_hash = $raw_hash . $hash;
    }
    my $encoded = encode_base64($raw_hash);
    $json_writer->add_property("hashes", $encoded);
    if (length($raw_hash) == 0) {
        $json_writer->add_property("length", "0");
    }
    else {
        $json_writer->add_property("length", $size);
    }
}

sub list_to_file {
    my $list = $_[0];
    return join("_", $list->{threatType}, $list->{platformType}, $list->{threatEntryType}) . ".gsb4";
}

sub make_tmp_dir {
    my $tmp = `mktemp -d`;
    $tmp =~ s/^\s+|\s+$//g; #trimming 
    $LOGGER->info("Created temporary folder for this session $tmp\n");
    return $tmp;
}

# this move all file from $src to $des
sub move_tmp_to_real {
    my ($src, $des) = @_;
    my @old_files = glob "$src/*";
    $des = $des . "/";
    foreach my $file (@old_files) {
        move($file, $des);
    }
}

sub get_last_update_in_extract_dir {
    my $last_update_file = $_[0] . "/last_update";
    if (open(my $fh, '<', $last_update_file)) {
        while (my $line = <$fh>) {
            chomp $line;
            return $line;
        }
    }
    else {
        warn "Could not open file [$last_update_file] $!";
        return 0;
    }
}

sub write_checksum_file {
    my $input_file_path = $_[0];
    my $cs_file_path = $input_file_path . ".cs";

    # compute checksum
    open(my $input_file_handle, $input_file_path) or die "Can't open file [$input_file_path]: $!";
    binmode($input_file_handle);
    my $md5 = Digest::MD5->new->addfile($input_file_handle)->hexdigest;
    close($input_file_handle) or die "Can't close file [$input_file_path]: $!";

    # write checksum
    open(my $cs_tmp_fh, '>', $cs_file_path) or die "Can't open file [$cs_file_path]: $!";
    print $cs_tmp_fh $md5;
    close($cs_tmp_fh) or die "Can't close [$cs_file_path]: $!";
    $LOGGER->info("Computed checksum of [$input_file_path]")
}

unless (caller()) {
    main();
}
