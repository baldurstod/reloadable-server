async function testBadRequest() {
	const response = await fetch('/test', {
		method: 'POST',
		headers : {
			'Content-Type': 'application/json',
		},
		body: {
			test: 1
		}
	});
}


testBadRequest();
