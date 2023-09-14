/**
 * Copyright (C) 2023 Paladin Business Solutions
 *
 */ 
function isNumberKey(evt){
    var charCode = (evt.which) ? evt.which : evt.keyCode
    if (charCode > 31 && (charCode < 48 || charCode > 57))
        return false;
            return true;
}
