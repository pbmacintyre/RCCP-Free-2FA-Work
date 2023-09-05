/**
 * Copyright (C) 2021 - 2023 Paladin Business Solutions
 *
 */ 

function reveal_it() {
	var y = document.getElementById("myGRCSite");    
    var z = document.getElementById("myGRCSecret");    

	if (y.type === "password") {
	  y.type = "text";
	}
	if (z.type === "password") {
	  z.type = "text";
	}
}

function hide_it() {
    var y = document.getElementById("myGRCSite");
    var z = document.getElementById("myGRCSecret");
	
	if (y.type === "text") {
	  y.type = "password";
	}
	if (z.type === "text") {
	  z.type = "password";
	}
}