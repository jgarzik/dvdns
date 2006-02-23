#!/usr/bin/perl -w
#
# Script to import a standard BIND zone file into the database.
#

use Net::DNS::RR;
use Net::DNS::ZoneFile::Fast;
use DBI qw(:sql_types);

my ($dbh, %dom_cache);
my $next_id = 1;

sub usage() {
	print STDERR "usage: import-zone.pl DATABASE ZONE-FILE\n";
	exit(1);
}

sub read_max_id() {
	my $sth = $dbh->prepare("select id from labels " .
				"order by id desc " .
				"limit 1");
	die "select id prep died\n" unless $sth;

	$sth->execute() or die "select id exec died";

	my (@data, $max_id);
	die "no row of data returned\n"
		unless @data = $sth->fetchrow_array();

	$max_id = $data[0];
	die "invalid max_id $max_id\n"
		unless ($max_id > 0);

	$next_id = $max_id + 1;
}

sub get_dom_id($) {
	my ($domain) = @_;

	return $dom_cache{$domain}
		if (exists $dom_cache{$domain});

	# obtain integer id associated with domain name, or create new one
	my $sth = $dbh->prepare('select id from labels where name = ?');
	die "select prep failed\n" unless $sth;

	$sth->execute($domain) or die "sql exec failed";

	if (($id) = $sth->fetchrow_array()) {
		$dom_cache{$domain} = $id;
		return $id;
	}

	return undef;
}

sub import_rr($) {
	my ($rr) = @_;
	my ($host, $domain, $id);

	# split domain name into "A" and "B.C.D" parts.
	if (!(($host, $domain) = ($rr->name =~ /^([^\.]+)\.(.*)$/))) {
		$host = $rr->name;
		$domain = "";
	}

	# get domain integer id, or create new one
	$id = get_dom_id($domain);
	if (!$id) {
		$id = $next_id;
		$next_id++;
		$dom_cache{$domain} = $id;

		my $ih = $dbh->prepare_cached('insert into labels values (?,?)');
		$ih->execute($domain, $id) or die "sql insert failed";
	}

	# build RR sql insert
	my $sth = $dbh->prepare_cached('insert into rrs values (?,?,?,?,?,?)');
	die "sql prep failed" unless $sth;

	$sth->bind_param(1, $host, SQL_VARCHAR);
	$sth->bind_param(2, $id, SQL_INTEGER);
	$sth->bind_param(3, Net::DNS::typesbyname($rr->type), SQL_INTEGER);
	$sth->bind_param(4, Net::DNS::classesbyname($rr->class), SQL_INTEGER);
	$sth->bind_param(5, $rr->ttl, SQL_INTEGER);
	$sth->bind_param(6, $rr->rdata, SQL_BLOB);

	$sth->execute() or die "sql exec failed";
}

sub import_zonefile($) {
	my ($fn) = @_;
	my ($rrs, $rr);

	$rrs = Net::DNS::ZoneFile::Fast::parse(
		'file'		=> $fn,
		'tolower'	=> 1
		);

	foreach $rr (@$rrs) {
		import_rr($rr);
	}

	$dbh->commit;
}


my $dbfn = shift;
usage() unless $dbfn;
$dbh = DBI->connect("dbi:SQLite:dbname=$dbfn", "", "",
		    { AutoCommit => 0 });
$dbh->{unicode} = 1;
die "connect($dbfn) failed: " . DBI->errstr . "\n"
	unless $dbh;

read_max_id();
$dom_cache{""} = 0;

my ($zonefn);
while ($zonefn = shift) {
	import_zonefile($zonefn);
}

$dbh->disconnect;

exit(0);

