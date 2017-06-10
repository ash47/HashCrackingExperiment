$(document).ready(function() {
	var doHashStuff = function() {
		var toHash = $('#hashField').val();

		if(toHash.length > 0) {
			window.location = '/' + encodeURIComponent(toHash) + '.htm?ignoreMaxLength=true';
		}
	};

	$('#hashPassword')
		.append(
			$('<input>', {
				id: 'hashField',
				type: 'text',
				placeholder: 'Enter a string to hash',
				keypress: function(e) {
					if(e.which == 13) {
						doHashStuff();
					}
				}
			})
		)
		.append(
			$('<input>', {
				class: 'btn btn-primary',
				type: 'button',
				value: 'Hash',
				click: doHashStuff
			})
		);
});