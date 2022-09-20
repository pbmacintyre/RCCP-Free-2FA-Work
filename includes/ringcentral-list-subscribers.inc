<?php
/**
 * Copyright (C) 2019-2021 Paladin Business Solutions
 *
 */ 

global $print_again, $wpdb;  

if( ! class_exists( 'WP_List_Table' ) ) {
    // in case the class is ever removed from WP Core use this copy
    require_once( ABSPATH . 'wp-content/plugins/ringcentral/includes/wp_list_class/class-wp-list-table.php' );
}

class RC_List_Table extends WP_List_Table {
    /* ===== constructor ==== */
    function __construct() {
        global $status, $page;
        parent::__construct( array(
            'singular'  => 'Subscriber',   //singular name of the listed records
            'plural'    => 'Subscribers'  //plural name of the listed records	           
        ) );
    }
    
    function column_default($item, $column_name) {
        return $item[$column_name];
    }
    
    function column_email($item) {
        $output = "<em><a href='mailto:$item[email]' target='_top'> " . $item['email'] . "</em>";
        return $output;
    }
    function column_email_optin_date($item) {
        if ($item['email_optin_date']) {
            $return_string = '<em>' . date('M j, Y',strtotime($item['email_optin_date'])) . '</em>';
        } else {
            $return_string = "";
        }
        return $return_string ;
    }
    function column_mobile($item) {
        return '<em><a href="sms:'.$item['mobile'].'">' . $item['mobile'] . '</a></em>';
    }
    function column_mobile_optin_date($item) {
        if ($item['mobile_optin_date']) {
            $return_string = '<em>' . date('M j, Y',strtotime($item['mobile_optin_date'])) . '</em>';
        } else {
            $return_string = "";
        }
        return $return_string ;
    }
    
    function column_full_name($item) {
        // $_REQUEST['page'] used so action will be done on curren page in delete a href string              
        $actions = array(            
            //'edit' => sprintf('<a href="?page=%s&action=edit&id=%s">%s</a>', $_REQUEST['page'], $item['ringcentral_contacts_id'], 'Edit'),
            'delete' => sprintf('<a href="?page=%s&action=delete&id=%s">%s</a>', $_REQUEST['page'], $item['ringcentral_contacts_id'], 'Delete')
        );
        return sprintf('%s %s',
            $item['full_name'],
            $this->row_actions($actions)
            );
    }
   
    function column_cb($item) {
        return sprintf(
            '<input type="checkbox" name="id[]" value="%s" />',
            $item['ringcentral_contacts_id']
            );
    }
   
    function get_columns() {
        $columns = array(
            'cb'                => '<input type="checkbox" />', //Render a checkbox instead of text
            'full_name'         => 'Subscriber Name',
            'email'             => 'EMail Address',
            'email_optin_date'  => 'EMail Opt-in Date',
            'mobile'            => 'Mobile #',
            'mobile_optin_date' => 'Mobile Opt-in Date'
        );
        return $columns;
    }
    
    function get_sortable_columns(){
        $sortable_columns = array(
            'full_name'         => array('full_name',true), //true means it's already sorted
            'email'             => array('email',false),
            'email_optin_date'  => array('email_optin_date',false),
            'mobile'            => array('mobile',false),
            'mobile_optin_date' => array('mobile_optin_date',false)
        );
        return $sortable_columns;
    }
   
    function get_bulk_actions() {
        $actions = array(
            'delete' => 'Delete'           
        );
        return $actions;
    }
    
    function process_bulk_action() {
        global $wpdb;
        $table_name = 'ringcentral_contacts'; 
        if ('delete' === $this->current_action()) {
            $ids = isset($_REQUEST['id']) ? $_REQUEST['id'] : array();
            if (is_array($ids)) $ids = implode(',', $ids);
            if (!empty($ids)) {
                $wpdb->query("DELETE FROM $table_name WHERE ringcentral_contacts_id IN($ids)");
            }
        }
    }
    
    function prepare_items($search = NULL) {
        global $wpdb;
        $table_name = 'ringcentral_contacts'; 
        $per_page = 10; // constant, how much records will be shown per page
        $columns = $this->get_columns();
        $hidden = array();
        $sortable = $this->get_sortable_columns();
        // here we configure table headers, defined in our methods
        $this->_column_headers = array($columns, $hidden, $sortable);
        // [OPTIONAL] process bulk action if any
        $this->process_bulk_action();
        // will be used in pagination settings
        $total_items = $wpdb->get_var("SELECT COUNT(`ringcentral_contacts_id`) FROM `$table_name`");
        // prepare query params, as usual current page, order by and order direction
        $paged = isset($_REQUEST['paged']) ? max(0, intval($_REQUEST['paged']) - 1) : 0;
        $orderby = (isset($_REQUEST['orderby']) && in_array($_REQUEST['orderby'], array_keys($this->get_sortable_columns()))) ? $_REQUEST['orderby'] : 'full_name';
        $order = (isset($_REQUEST['order']) && in_array($_REQUEST['order'], array('asc', 'desc'))) ? $_REQUEST['order'] : 'asc';
        
        /* If the value is not NULL, do a search for it. */
        if( $search != NULL ){
            
            // Trim and sanitize Search Term
            $search = trim($search) ;
            
            /* Notice how you can search multiple columns for your search term easily, and return one data set */
            $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE `full_name` LIKE '%%%s%%' OR `email` LIKE '%%%s%%'
                ORDER BY $orderby $order LIMIT %d OFFSET %d", $search, $search, $per_page, $paged);
           // echo $sql ;
            $this->items = $wpdb->get_results($sql, ARRAY_A);            
        } else {
            $this->items = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name
                ORDER BY $orderby $order LIMIT %d OFFSET %d", $per_page, $paged), ARRAY_A);
        }
        
        // [REQUIRED] configure pagination
        $this->set_pagination_args(array(
            'total_items' => $total_items, // total items defined above
            'per_page' => $per_page, // per page constant defined at top of method
            'total_pages' => ceil($total_items / $per_page) // calculate pages count
        ));
    }

} //class

$myListTable = new RC_List_Table();

if( isset($_REQUEST['s']) ){
    $myListTable->prepare_items($_REQUEST['s']);
} else {
    $myListTable->prepare_items();
}

$current_action = $myListTable->current_action() ;

if ($current_action !== 'delete' && $current_action !== 'edit') {
    ?>
    <div style="background:#ECECEC;border:1px solid #CCC;padding:0 10px;margin-top:5px;border-radius:5px;-moz-border-radius:5px;-webkit-border-radius:5px;">
    	<p>Manage your subscriber information here</p>
    </div>   
    <?php 
}

if ($current_action === 'delete') {
    $message = '<div class="updated below-h2" id="message"><p>' 
        . sprintf('Items deleted: %d', count($_REQUEST['id'])) . '</p></div>';
}

if ($current_action === 'edit') {
    // bring in the edit form
    $edit_path = RINGCENTRAL_PLUGIN_INCLUDES . 'ringcentral-edit-subscribers.inc' ;    
    require_once($edit_path);
} else {
    ?>     
    <h2><?php echo 'Subscribers' ; ?> 
    	<a class="add-new-h2" href="admin.php?page=ringcentral_add_subs">Add New</a>
    </h2>    
    <?php echo $message; ?>             
    <!-- Forms are NOT created automatically, so you need to wrap the table in one to use features like bulk actions -->
    <form method="get">
        <!-- For plugins, we also need to ensure that the form posts back to our current page -->
        <input type="hidden" name="page" value="<?php echo $_REQUEST['page'] ?>" />
        <?php $myListTable->search_box('Search', 'search_id'); ?>
        <!-- Now we can render the completed list table -->
        <?php $myListTable->display() ?>
    </form>
<?php } ?>