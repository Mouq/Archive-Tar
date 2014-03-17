### the gnu tar specification:
### http://www.gnu.org/software/tar/manual/tar.html
###
### and the pax format spec, which tar derives from:
### http://www.opengroup.org/onlinepubs/007904975/utilities/pax.html

use X::Archive::Tar;
class Archive::Tar;

# May want this to accept arguments
# at some point, maybe passing
# :file(*) and *%_ along to .read
multi method new ($file, *%config) {
    self.read($file, |%config)
}

constant HEAD       = 512;
constant BLOCK      = 512;
constant TAR_END    = Buf.new: 0 xx BLOCK;
constant PAX_HEADER = 'pax_global_header';
my sub block_size { my $n = ($^s/BLOCK).Int; $n++ if $^s % BLOCK; $n * BLOCK };

our sub read-tar (|a --> Archive::Tar) is export {
    Archive::Tar.read(|a);
}
proto method read (|) returns Archive::Tar {*}
multi method read (Str $file, |conf) {
    self.read($file.IO, |conf)
}
multi method read (IO::Handle $file,
                   :$gzip, :$bzip,
                   # X ~~ * always returns True
                   :$filter = *,
                   :$limit,
                   :$md5, :$extract,
                  )
{
    # XXX "die"|"warn" -> Exception
    $gzip | $bzip and die "Decompression NYI";
    die "$file is not a file" unless $file ~~ :f;
    $file.open(:bin)          unless $file ~~ :opened;

    # Read tar
    my $count = $limit;
    my $real_name;
    my $data;
    my $tarfile; # ??
    while $file.read(512) -> $chunk {
        NEXT { $data = '' }
        my $offset = $file.tell;

        unless (state $first)++ {
            ### size is < HEAD, which means a corrupted file, as the minimum
            ### length is _at least_ HEAD
            warn "Cannot read enough bytes from the tarfile"
                if $chunk.elems != HEAD;
        }

        ### if we can't read in all bytes... ###
        last if $chunk.elems != HEAD;

        ### Apparently this should really be two blocks of 512 zeroes,
        ### but GNU tar sometimes gets it wrong. See comment in the
        ### source code (tar.c) to GNU cpio.
        next if $chunk eq TAR_END;

        ### according to the posix spec, the last 12 bytes of the header are
        ### null bytes, to pad it to a 512 byte block. That means if these
        ### bytes are NOT null bytes, it's a corrupt header. See:
        ### www.koders.com/c/fidCE473AD3D9F835D690259D60AD5654591D91D5BA.aspx
        ### line 111
        do {
            my $nulls = ("\0" x 12).encode;
            unless $nulls eq $chunk.subbuf(500, 12) {
                    warn "Invalid header block at offset $offset";
                    next;
                }
        }

        ### pass the realname, so we can set it 'proper' right away
        ### some of the heuristics are done on the name, so important
        ### to set it ASAP
        my $entry;
        unless $entry = Archive::Tar::File.new: :$chunk, :name($real_name) {
            warn "Couldn't read chunk at offset $offset";
            next;
        }

        ### ignore labels:
        ### http://www.gnu.org/software/tar/manual/html_chapter/Media.html#SEC159
        next if $entry.is_label;

        if $entry.type.chars and ($entry.is_file || $entry.is_longlink) {
            if $entry.is_file && !$entry.validate {
                ### sometimes the chunk is rather fux0r3d and a whole 512
                ### bytes ends up in the .name area.
                ### clean it up, if need be
                my $name = $entry.name;
                $name = substr($name, 0, 100) if $name.chars > 100;
                $name ~~ s:g/\n/ /;
                warn "$name: checksum error";
                next;
            }
            
            my $block = block_size $entry.size;

            $data = $entry.get_content_by_ref;

            my $skip = 0;
            my $ctx;                        # cdrake
            ### skip this entry if we're filtering
 
            if $md5 {                       # cdrake
                $ctx = Digest::MD5.new;     # cdrake
                $skip = 5;                  # cdrake
 
            }
            elsif $entry.name !~~ $filter {
                $skip = 1;
            } 
            ### skip this entry if it's a pax header. This is a special file added
            ### by, among others, git-generated tarballs. It holds comments and is
            ### not meant for extracting. See #38932: pax_global_header extracted
            elsif $entry.name eq PAX_HEADER or $entry.type eq 'x'|'g' {
                $skip = 2;
            }
            #elsif $filter_cb && ! $filter_cb.($entry)) {
            #    $skip = 3;
            #}
 
            if $skip {
                #
                # Since we're skipping, do not allocate memory for the
                # whole file.  Read it 64 BLOCKS at a time.  Do not
                # complete the skip yet because maybe what we read is a
                # longlink and it won't get skipped after all
                #
                my $amt = $block;
                my $fsz = $entry.size;        # cdrake
                my $next-outer; # XXX Loop labels NYI
                while $amt > 0 {
                    $data = '';
                    my $this = 64 * BLOCK;
                    $this = $amt if $this > $amt;
                    if ($data = $file.read( $this )) < $this {
                        warn "Read error on tarfile (missing data) '$entry.full_path()' at offset $offset";
                        $next-outer++ and last;
                    }
                    $amt -= $this;
                    $fsz -= $this;                              # cdrake
                    # remove external junk prior to md5         # cdrake
                    substr($data, $fsz) = "" if ($fsz < 0);   # cdrake
                    $ctx.add($data) if($skip==5);             # cdrake
                }
                next if $next-outer;
                $data = $ctx.hexdigest # cdrake
                    if $skip == 5 && !$entry.is_longlink && !$entry.is_unknown && !$entry.is_label; # cdrake
            } else {
                ### just read everything into memory
                ### can't do lazy loading since IO::Zlib doesn't support 'seek'
                ### this is because Compress::Zlib doesn't support it =/
                ### this reads in the whole data in one read() call.
                if ( $file.read( $data, $block ) < $block ) {
                    warn "Read error on tarfile (missing data) '$entry.full_path()' at offset $offset";
                    next;
                }
                ### throw away trailing garbage ###
                $data.=substr(0, $entry.size) if $data.defined;
            }
 
            ### part II of the @LongLink munging -- need to do /after/
            ### the checksum check.
            if $entry.is_longlink {
                ### weird thing in tarfiles -- if the file is actually a
                ### @LongLink, the data part seems to have a trailing ^@
                ### (unprintable) char. to display, pipe output through less.
                ### but that doesn't *always* happen.. so check if the last
                ### character is a control character, and if so remove it
                ### at any rate, we better remove that character here, or tests
                ### like 'eq' and hash lookups based on names will SO not work
                ### remove it by calculating the proper size, and then
                ### tossing out everything that's longer than that size.
 
                ### count number of nulls
                my $nulls = +$data.comb("\0");
 
                ### cut data + size by that many bytes
                $entry.size( $entry.size - $nulls );
                $data.=substr(0, $entry.size);
            }
        }

        ### clean up of the entries.. posix tar /apparently/ has some
        ### weird 'feature' that allows for filenames > 255 characters
        ### they'll put a header in with as name '././@LongLink' and the
        ### contents will be the name of the /next/ file in the archive
        ### pretty crappy and kludgy if you ask me
 
        ### set the name for the next entry if this is a @LongLink;
        ### this is one ugly hack =/ but needed for direct extraction
        if $entry.is_longlink {
            $real_name = $data;
            next;
        } elsif defined $real_name {
            $entry.name( $real_name );
            $entry.prefix('');
            $real_name = '';
        }
 
        if $entry.name !~~ $filter {
            next;
        }
        ### skip this entry if it's a pax header. This is a special file added
        ### by, among others, git-generated tarballs. It holds comments and is
        ### not meant for extracting. See #38932: pax_global_header extracted
        elsif $entry.name eq PAX_HEADER or $entry.type eq 'x'|'g' {
            next;
        }
        #elsif $filter_cb && ! $filter_cb.($entry) {
        #    next;
        #}
 
        if $extract && !$entry.is_longlink
                    && !$entry.is_unknown
                    && !$entry.is_label {
            self._extract_file( $entry ) or return;
        }
 
        ### Guard against tarfiles with garbage at the end
        last if $entry.name eq '';
 
        ### push only the name on the rv if we're extracting
        ### -- for extract_archive
        push $tarfile, ($extract ?? $entry.name !! $entry);
 
        if $limit {
            $count-- unless $entry.is_longlink || $entry.is_dir;
            last unless $count;
        }
    }
    $tarfile;
}
