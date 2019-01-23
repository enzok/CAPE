rule Base64EncodedExecutable {
	meta:
		description = "Base64 Encoded Executable Payload"
        cape_type = "Base64 Encoded Executable Payload"
		author = "Florian Roth"
		date = "2015-05-28"
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA"
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA"
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA"
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA"
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA"
	condition:
		1 of them
}