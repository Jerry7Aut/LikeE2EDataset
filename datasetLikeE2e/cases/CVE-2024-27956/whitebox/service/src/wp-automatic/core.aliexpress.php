<?php

// Main Class
require_once 'core.php';
class WpAutomaticaliexpress extends wp_automatic {
	
	function aliexpress_get_post($camp) {
		
		
		
		 
		// ini keywords
		$camp_opt = unserialize ( $camp->camp_options );
		$keywords = explode ( ',', $camp->camp_keywords );
		$camp_general = unserialize ( base64_decode ( $camp->camp_general ) );
		
		
		if( in_array('OPT_ALIEXPRESS_CUR',$camp_opt ) ){
			
			$cg_ae_custom_cur = wp_automatic_trim($camp_general['cg_ae_custom_cur']);
			echo '<br>Custom currency is requested...'  .  $cg_ae_custom_cur;
			
			//price cookie aep_usuc_f=site=ara&c_tp=CAD
			$cookie_value = $this->cookie_content('aliexpress');
			
			if( ! stristr(  $cookie_value ,  'c_tp=' . $cg_ae_custom_cur   )){
				echo ' Found not set, let us set it ' ;
				$this->cookie_delete('aliexpress');
				
				$aep_usuc_f = 'aep_usuc_f=c_tp=' . $cg_ae_custom_cur;
				
				//global domain name site=glo
				if(! in_array('OPT_ALIEXPRESS_DOMAIN' , $camp_opt)){
					$aep_usuc_f.= '&site=glo&b_locale=en_US';
				}
				
				curl_setopt($this->ch,CURLOPT_COOKIE, $aep_usuc_f );
				
			}else{
				echo ' Currency is already set to ' . $cg_ae_custom_cur ;
			}
			
			
		}else{
			
			if(! in_array('OPT_ALIEXPRESS_DOMAIN' , $camp_opt)){
			
				//no currency is required but lets make sure that the domain is set to glo
				//price cookie aep_usuc_f=site=ara&c_tp=CAD
				$cookie_value = $this->cookie_content('aliexpress');
				
				if( ! stristr(  $cookie_value ,  'site=glo'     )){
					echo '<br>Found site glo not set, let us set it ' ;
					$this->cookie_delete('aliexpress');
					
					$aep_usuc_f = 'aep_usuc_f=site=glo&c_tp=USD&isb=y&b_locale=en_US'  ;
					
					curl_setopt($this->ch,CURLOPT_COOKIE, $aep_usuc_f );
					
				}else{
					echo '<br>Site found set to Glo' ;
				}
				
			}
			
			
		}
		
		//  cookie load
		$this->load_cookie ( 'aliexpress' );
		
		// looping keywords
		foreach ( $keywords as $keyword ) {
			
			$keyword = wp_automatic_trim( $keyword );
			
			// update last keyword
			update_post_meta ( $camp->camp_id, 'last_keyword', wp_automatic_trim( $keyword ) );
			
			// when valid keyword
			if (wp_automatic_trim( $keyword ) != '') {
				
				// record current used keyword
				$this->used_keyword = $keyword;
				
				echo '<br>Let\'s post AliExpress product for the key:' . $keyword;
				
				
				// getting links from the db for that keyword
				$query = "select * from {$this->wp_prefix}automatic_general where item_type=  'ae_{$camp->camp_id}_$keyword' ";
				$res = $this->db->get_results ( $query );
				
				// when no links lets get new links
				if (count ( $res ) == 0) {
					
					// clean any old cache for this keyword
					$query_delete = "delete from {$this->wp_prefix}automatic_general where item_type='ae_{$camp->camp_id}_$keyword' ";
					$this->db->query ( $query_delete );
					
					// get new links
					$this->aliexpress_fetch_items ( $keyword, $camp );
					
					// getting links from the db for that keyword
					$res = $this->db->get_results ( $query );
				}
				
				// check if already duplicated
				// deleting duplicated items
				
				$item_count = count ( $res );
				
				for($i = 0; $i < $item_count; $i ++) {
					
					$t_row = $res [$i];
					
					$t_data = unserialize ( base64_decode ( $t_row->item_data ) );
					
					
					
					$t_link_url = $t_data ['item_url'];
					
					echo '<br>Link:' . $t_link_url ;
					
				 
					
					// check if link is duplicated
					if ($this->is_duplicate ( $t_link_url )) {
						
						// duplicated item let's delete
						unset ( $res [$i] );
						
						echo '<br>AliExpress product (' . $t_data ['item_url'] . ') found cached but duplicated <a href="' . get_permalink ( $this->duplicate_id ) . '">#' . $this->duplicate_id . '</a>';
						
						// delete the item
						$query = "delete from {$this->wp_prefix}automatic_general where id={$t_row->id}";
						$this->db->query ( $query );
					} else {
						
						break;
					}
				} // end for
				
				// check again if valid links found for that keyword otherwise skip it
				if (count ( $res ) > 0) {
					
					// lets process that link
					$ret = $res [$i];
					
					$temp = unserialize ( base64_decode ( $ret->item_data ) );
					
					//get the item info for this video
					$current_item_url = $temp['item_url'];
				 	
					// update the link status to 1
					$query = "delete from {$this->wp_prefix}automatic_general where id={$ret->id}";
					$this->db->query ( $query );
					
					//curl get
					$x='error';
					
					curl_setopt($this->ch, CURLOPT_HTTPGET, 1);
					curl_setopt($this->ch, CURLOPT_URL, wp_automatic_trim($current_item_url));
					//curl_setopt($this->ch,CURLOPT_COOKIE,'cna=7pA+GcdD33QCAZrvFdNMnJrh; af_ss_a=1; ali_apache_id=33.0.189.215.1653278887120.170435.8; intl_locale=en_US; aeu_cid=0bd51a4fc7c045548c8eeba826940237-1653278916149-00629-_AKj8bL; af_ss_b=1; e_id=pt20; _gid=GA1.2.227719103.1653278920; _gcl_au=1.1.1927482556.1653278920; XSRF-TOKEN=44c71125-95fa-47fe-8f98-b4318325a006; xlly_s=1; _hvn_login=13; ali_apache_tracktmp=W_signed=Y; acs_usuc_t=acs_rt=3586d9eec4c840388852c263d80a4e4d&x_csrf=rm0icrabemj0; havana_tgc=eyJjcmVhdGVUaW1lIjoxNjUzMjc5NDM1NjM1LCJsYW5nIjoiZW5fVVMiLCJwYXRpYWxUZ2MiOnsiYWNjSW5mb3MiOnsiMTMiOnsiYWNjZXNzVHlwZSI6MSwibWVtYmVySWQiOjE1NzYzOTM2MTQzODksInRndElkIjoiNnE4bEJvaDJsenBSZkNBLTNXekMxemcifX19fQ; sgcookie=E100ijC%2Fqe49VhlsEwolVTKY0ULxg7SuW6crRh06e6SQJ6W9uMOJSq7ZXkmhHLJ8Ih1vvcLFZbKKQhbcfr4w1vw68Q%3D%3D; aep_usuc_t=ber_l=A0; aep_common_f=inyfuCxQ08ABJxYlj00+HxXs7gkyo1C4HwWrNtedcG/LGMsZL5CnEw==; ali_apache_track=mt=1|ms=|mid=eg2092938711ozaae; xman_us_t=x_lid=eg2092938711ozaae&sign=y&rmb_pp=sweetheatmn@gmail.com&x_user=mgBoN8Qu8pgVvO5ayHo0iXQwbS0PG22PHqxA7y7xuLA=&ctoken=xwgtjpe8cx_4&need_popup=y; bx_s_t=Bnq/8c4en5qEbROgMnBe1xLbxE78JoNm1QWr4br+To30Yv7eltERmmWHiSMve/BeoqTWR5eAf+d/ss2dVA1qGPL/jCxJNXLbDWV/2sM0uvI=; xman_f=ZyQJ//uy7HYvn0Z8+N6z9J+SC+aOHeUSNMPnztC4MxHLboYy0porkwCGbWpYwi6l0HQBQbYhggjsE136VZiKRvqhXrGCezCuJCGDZesMP0w8wDla75nD1ZiojU0P+gIHeqtvn8HLFGMAvlm+2CbXKqKYEfePsKHzB786HuyQtkN4/HrbxuhseIlZ9hID0ySLMX8jrSZPBeWEe4oa0OpsB8/rqzaWNbn7p+LfY/2+5AxkWNfZTHJU/IzKsP63bc6agjcOQamrc1uXWB4t7IS3Pv8VR5xXfotpk0NDiwyNOVF08HPgqPr++Ts+e+msFQfrZIZdA8+aMjUD97R0dV6UsMODfdMtqMx3dahhkn7RdS1KqlX366kyMHvHoqGQp7W64LPxsbFsW6ytpkq806MGHc6gRk2U2xUtkwg7ol2anH8MIdGbyUwro5YzZcE0F1Re; aep_usuc_f=site=glo&c_tp=USD&x_alimid=3695442719&isb=y&region=EG&b_locale=en_US; traffic_se_co=%7B%7D; aep_history=keywords%5E%0Akeywords%09%0A%0Aproduct_selloffer%5E%0Aproduct_selloffer%091005001840919538%091005003141253710; _m_h5_tk=02113d13c876a7e43867aa4ab11393c5_1653287207173; _m_h5_tk_enc=7e3f04d7d5bd6075d9ec022c8333868a; xman_us_f=x_locale=en_US&x_l=0&last_popup_time=1653279304812&x_user=EG|sweetheatmn|user|ifm|3695442719&no_popup_today=n&x_lid=eg2092938711ozaae&x_c_chg=0&x_c_synced=0&x_as_i=%7B%22aeuCID%22%3A%220bd51a4fc7c045548c8eeba826940237-1653278916149-00629-_AKj8bL%22%2C%22af%22%3A%228576346%22%2C%22affiliateKey%22%3A%22_AKj8bL%22%2C%22channel%22%3A%22AFFILIATE%22%2C%22cv%22%3A%221%22%2C%22isCookieCache%22%3A%22N%22%2C%22ms%22%3A%220%22%2C%22pid%22%3A%221933645790%22%2C%22tagtime%22%3A1653278916149%7D&acs_rt=752658651e9e44d0b093874dfbf2a25f; AKA_A2=A; l=eBQ5JzleOsGFkx_LBOfanurza77tjIRbouPzaNbMiOCPszCe5JscB6fGbtYwCnMNnsAMR3-4a-MXBPTauyUGRxv9-egKWoqK3dTh.; tfstk=cxE1Bdvu2SEeDdQ2bR6F0DSATVicZHOIKNGUC6G3z4lD8j21ijtrNlMUoBiqHv1..; isg=BE9PkWm5cc0M5kh0DYZ_y6JZ3uVZdKOWomyZdGFc477FMG4yaUe15tkiNniOTnsO; _ga_VED1YSGNC7=GS1.1.1653285136.2.1.1653285150.0; _ga=GA1.1.2005559545.1653278920; xman_t=IxxVatIOZjAtzcMX7/PojANYCEV7WvVrUDPurbWG1f4SH0ikoK7R9wFnkoPXb/n3t1USTktgVjsnVujiQY9ygvh/Qkq4RvMGseWLqCoS3HMX4A7W+MkHR6qWAiY+kKmtQOn42MI2PPukeBszI2OLXGpaINdtu4pO/D12Z8nYZV9pmAOWn5Mnm82fXzltPt/QRnPt9kOFBI0W61tOKMSY/LiwU3O0o/wua2rt8OPFuUnmfch1couA/aJYx/HjH/ZUJ83Tg7gyZFfiOvOjH1XOcZzqP6nqBBMqAkRM/PKfQgOMoy4JDsQ1qAfy5HR5smAdYrRC0dfoeq7PBS8OTkJfUpP2ayDziHHbAHKYrOWcMPHuznZgq2ySv6OC4nsqg6Jzr5Udae2YkWUBPtDHmgK+oCkBffjhVu0v6hcBr8rycO5dNqdJdOm8/DsghIkIKBZe0pItu7X8ZRPs3DqEC+UWhKSeMguY5F694egxy5Pz2XkFaFj0UOLOKE7JgixJkEAWdYdURubFrqfp9xGqkGfHr7KoIWXHO26uQMyLI7RNpQR/W061b2YqZTNBIFQG2AYe8TEn1POiRWlZHIuRjyJqCpAiF5WM1EErAp1uVhut8xfazBlyr2guTsaBVsEqLRsB9b/S7Cm34yokT1dV7jKrlTVqwosOLlE7a1r6FM6W6gE=; JSESSIONID=52AFB6D23C73E14B7969157A25C3F1D9; intl_common_forever=Hk3Bem39XVdTHERchWmIP1gSjfq2slkiT9XXZbFueoI8idR24P0xdg==; RT="z=1&dm=aliexpress.com&si=6ff724e4-3243-4592-8f53-5ff34d488395&ss=l3ibaerg&sl=1&tt=42y&rl=1&ld=432&ul=1za8"');
					$exec=curl_exec($this->ch);
					$x=curl_error($this->ch);
			 
 					
					//validating reply, i.e e,"productId
					if( ! stristr($exec, '"productId')){
						echo '<br><-- Could not get a valid reply ' . $exec;
						return false;
					}
					
				
					//extract json window.runParams = ...};
					echo '<br>Nice, we got the product page, lets find the JSON...';
					preg_match('!window.runParams \= ({.*?});!s' , $exec , $json_match );
					
					
					//validating the return 
					if(wp_automatic_trim($json_match[1] == '')){
						echo '... empty match...';
						return false;
					}
					
					if(! stristr($exec, 'data:')){
						echo '.. Json found, data not found';
						return false;
					}
				
					//title "subject"
					preg_match('!"subject":"(.*?)"!' , $json_match[1] , $title_matchs);
					$temp['item_title'] = $title_matchs[1];
					 
					//rating "averageStar":"4.6"
					preg_match('!ageStar":"(.*?)"!' , $json_match[1] , $rating_matchs);
					$temp['item_rating'] = $rating_matchs[1];
					
					//TradeCount":"127"
					preg_match('!TradeCount":"(.*?)"!' , $json_match[1] , $found_matchs);
					$temp['item_orders'] = $found_matchs[1];
					
					//item_price_current defaults to original price
					//originalPrice ,"originalPrice":"US $1.75"
					//new "origPrice":{"minAmount":{"currency":"EGP","formatedAmount":"EGP24.12"
					$temp['item_price_current'] = '';
					preg_match('!"origPrice.*?formatedAmount":"(.*?)"!' , $json_match[1] , $found_matchs);
					if( isset($found_matchs[1]) ) $temp['item_price_current'] = $found_matchs[1];

					//if original price was extracted, set the  item_price_original to it
					if(wp_automatic_trim($temp['item_price_current']) != ''){
						$temp['item_price_original'] = $temp['item_price_current'];
					}

					//price formatedActivityPrice":"US $0.12 - 0.83"," 
					//new "skuActivityAmount":{"currency":"USD","formatedAmount":"US $1.39","value":1.39}}
					preg_match('!ActivityAmount".*?formatedAmount":"(.*?)"!' , $json_match[1] , $found_matchs);
					
	
					//if activity price is available overwrite the current price with it
					if(isset($found_matchs[1] ) )
					$temp['item_price_current'] = $found_matchs[1];
					
					//if price current was not available fallback to formatedPrice
					//},"formatedPrice":"US $0.69 - 0.88
					//new "formatedAmount":"US $0.77"
					preg_match('!"formatedAmount":"(.*?)"!' , $json_match[1] , $found_matchs);
					if(isset($found_matchs[1] ) && wp_automatic_trim($temp['item_price_current']) == '')
						$temp['item_price_current'] = $found_matchs[1];
					 
					//if $temp['item_price_original'] is not set, set it to the current price
					if(wp_automatic_trim($temp['item_price_original']) == ''){
						$temp['item_price_original'] = $temp['item_price_current'];
					}
 
					//images list imagePathList":["...."]
					preg_match('!"imagePathList":\["(.*?)"\]!' , $json_match[1] , $found_matchs);
					$temp['item_images'] = wp_automatic_str_replace('","' , ',' , $found_matchs[1]);
					
					//ship from "shipFrom":"China
					preg_match('!"shipFrom":"(.*?)"!' , $json_match[1] , $found_matchs);
					$temp['item_ship_from'] = $found_matchs[1];
					
					//deliveryDayMax
					preg_match('!"deliveryDayMax":(.*?),!' , $json_match[1] , $found_matchs);
					$temp['item_delivery_time'] = $found_matchs[1];
					
					// ormattedAmount":"US $0.93","shipFrom"
					preg_match('!"formattedAmount":"([^"]*?)","shipFrom!' , $json_match[1] , $found_matchs);
					$temp['item_ship_cost'] = isset($found_matchs[1]) ? $found_matchs[1] : '' ;
					
					//"itemWishedCount":232,"
					preg_match('!"itemWishedCount":(.*?),!' , $json_match[1] , $found_matchs);
					$temp['item_wish_count'] = $found_matchs[1];
					
					//descriptionUrl "descriptionUrl":"https://aep
					preg_match('!"descriptionUrl":"(.*?)"!' , $json_match[1] , $found_matchs);
					$temp['item_description_url'] = $found_matchs[1];

					
					// report link
					echo '<br>Found Link:' . $temp ['item_url'];
					
					
					
					// if cache not active let's delete the cached videos and reset indexes
					if (! in_array ( 'OPT_AE_CACHE', $camp_opt )) {
						echo '<br>Cache disabled claring cache ...';
						$query = "delete from {$this->wp_prefix}automatic_general where item_type='ae_{$camp->camp_id}_$keyword' ";
						$this->db->query ( $query );
						
						// reset index
						$query = "update {$this->wp_prefix}automatic_keywords set keyword_start =1 where keyword_camp={$camp->camp_id}";
						$this->db->query ( $query );
						
						 
					}
					 
					// imgs html
					if(in_array('OPT_AM_FULL_IMG' , $this->camp_opt)){
						$cg_am_full_img_t = stripslashes(@$camp_general ['cg_ae_full_img_t']);
					}else{
						$cg_am_full_img_t = '' ;
					}
					
					
					
					if (wp_automatic_trim( $cg_am_full_img_t ) == '') {
						$cg_am_full_img_t = '<img src="[img_src]" class="wp_automatic_gallery" />';
					}
					
					$product_imgs_html = '';
					
					$allImages = explode ( ',', $temp ['item_images'] );
					$allImages_html = '';
					
					foreach ( $allImages as $singleImage ) {
						
						//first image
						if(! isset($temp['item_img'])) $temp['item_img'] = $singleImage;
						
						$singleImageHtml = $cg_am_full_img_t;
						$singleImageHtml =wp_automatic_str_replace( '[img_src]', $singleImage, $singleImageHtml );
						$allImages_html .= $singleImageHtml;
					}
					
					$temp ['item_imgs_html'] = $allImages_html;
					
					// item images ini
					$temp ['item_image_html'] = '<img src="' . $temp ['item_img'] . '" />';
					 
					//get description content from descriptionUrl
					if(wp_automatic_trim($temp['item_description_url'])  != '' ){
						echo '<br>Finding item description from description URL:' . $temp['item_description_url'];
						
						//curl get
						$x='error';
						$url=$temp['item_description_url'];
						curl_setopt($this->ch, CURLOPT_HTTPGET, 1);
						curl_setopt($this->ch, CURLOPT_URL, wp_automatic_trim($url));
						$exec=curl_exec($this->ch);
						$x=curl_error($this->ch);
						
					 	$temp['item_description'] = $exec;
						
					}
					
					
					
					$temp['item_price_numeric'] =  $this->get_numberic_price($temp['item_price_current']);
					$temp['item_price_original_numeric'] =  $this->get_numberic_price($temp['item_price_original']);
					 
					//generating affiliate link
					echo '<br>Generating affiliate link... ';
					$temp['item_affiliate_url'] = $temp['item_url']; // ini
					
					$wp_automatic_ali_cookie = wp_automatic_trim(get_option( 'wp_automatic_ali_cookie' , '' ));
					$wp_automatic_ali_cookie_f = wp_automatic_trim(get_option( 'wp_automatic_ali_cookie_f' , '' ));
					$wp_automatic_ali_tracking_id = wp_automatic_trim(get_option('wp_automatic_ali_tracking_id' , ''));
					
					//verify if cookie is added
					if( $wp_automatic_ali_cookie  == '' || $wp_automatic_ali_cookie_f == '' || $wp_automatic_ali_tracking_id == ''){
						echo '<br><span style="color:orange">WARNING! You did not add the required AliExpress cookies and traking ID on the plugin settings page for affiliate link generation, we will use the regular link instead...</span>';
					}else{
						
						//fine we have a cookie
						echo '<-- cookie is added, lets start';
						
						//curl cookie reset CURLOPT_COOKIELIST
						curl_setopt($this->ch, CURLOPT_COOKIELIST, 'ALL');
						
						//curl post

						//build affiliate link generation page on form https://portals.aliexpress.com/tools/linkGenerate/generatePromotionLink.htm?trackId=sweetheatmn&targetUrl=https%3A%2F%2Far.aliexpress.com%2Fitem%2F1005004896243854.html
							https://portals.aliexpress.com/tools/linkGenerate/generatePromotionLink.htm?trackId=sweetheatmn&targetUrl=https%3A%2F%2Far.aliexpress.com%2Fitem%2F1005004896243854.html
						
						//dedicated handle for link geneartion
						$cu = curl_init();

						curl_setopt_array($cu, array(
							CURLOPT_URL => 'https://portals.aliexpress.com/tools/linkGenerate/generatePromotionLink.htm?trackId='. $wp_automatic_ali_tracking_id .'&targetUrl='.urlencode($temp['item_url']),
							CURLOPT_RETURNTRANSFER => true,
							CURLOPT_ENCODING => '',
							CURLOPT_MAXREDIRS => 10,
							CURLOPT_TIMEOUT => 0,
							CURLOPT_FOLLOWLOCATION => true,
							CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
							CURLOPT_CUSTOMREQUEST => 'GET',
							CURLOPT_HTTPHEADER => array(
							  'authority: portals.aliexpress.com',
							  'accept: application/json, text/plain, */*',
							  'accept-language: en-US,en;q=0.9,ar;q=0.8',
							  'bx-v: 2.5.1',
							  'cookie: xman_t='.$wp_automatic_ali_cookie. ';xman_f='.$wp_automatic_ali_cookie_f,
							  'referer: https://portals.aliexpress.com/affiportals/web/link_generator.htm',
							  'sec-ch-ua: "Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"',
							  'sec-ch-ua-mobile: ?0',
							  'sec-ch-ua-platform: "macOS"',
							  'sec-fetch-dest: empty',
							  'sec-fetch-mode: cors',
							  'sec-fetch-site: same-origin',
							  'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
							),
						  ));
						 
						
						
						
						$x='error';
						$exec=curl_exec($cu);
						$x=curl_error($cu);
					 
						
						if($exec == ''){
							echo '<--Fail: empty reply with a possible cURL error '. $x;
						}

						//correct response {"code":"00","data":"https://s.click.aliexpress.com/e/_DkjzHO3","success":true}
						if( ! stristr($exec, '{"code') ){
							echo '<--Fail: Did not get the expected link generation page, maybe the added cookie is not correct or expired';
							
							//login page? fm-login-id
							if(stristr($exec,'fm-login-id')){
								echo '<-- Got a login page instead, your cookie is expired/not correct for sure';
								
								$this->notify_the_admin('wp_automatic_ali_cookie' , 'Last call to AliExpress promote link page did not work, AliExpress cookie needs to be updated');
								
							}
							
						}else{
							echo '<-- nice, got the link generation page already';
						}
						 
						if(stristr($exec,'"success":true') && stristr($exec,'"data"') ){
							preg_match('!"data":"(.*?)"!s', $exec , $possible_lnks);
						}
						
						   
						if(isset($possible_lnks[1]) && wp_automatic_trim($possible_lnks[1]) != '' && stristr($possible_lnks[1], 'http') ){
							echo '<br>Affiliate link generated successfully: ' . $possible_lnks[1];
							$temp['item_affiliate_url']  = wp_automatic_trim($possible_lnks[1]);
							
						}else{
							echo '<br>Was not able to get an affiliate link, we will use the normal link instead';
							
							/*print_r($possible_lnks);
							echo $exec;*/
						}
					}
					
					
						
					
					/*
					echo '<pre>';
					print_r($temp);
					 
						  */
					
					
					return $temp;
				} else {
					echo '<br>No links found for this keyword';
				}
			} // if trim
		} // foreach keyword
	}
	function aliexpress_fetch_items($keyword, $camp) {
		
		// report
		echo "<br>So I should now get some items from AliExpress for keyword :" . $keyword;
  
		// Amazon cookie
		$this->load_cookie ( 'aliexpress' );
		
		
		// ini options
		$camp_opt = unserialize ( $camp->camp_options );
		if (stristr ( $camp->camp_general, 'a:' ))
			$camp->camp_general = base64_encode ( $camp->camp_general );
			
			$camp_general = unserialize ( base64_decode ( $camp->camp_general ) );
			$camp_general = array_map ( 'wp_automatic_stripslashes', $camp_general );
			
			// get start-index for this keyword
			$query = "select keyword_start ,keyword_id from {$this->wp_prefix}automatic_keywords where keyword_name='$keyword' and keyword_camp={$camp->camp_id}";
			$rows = $this->db->get_results ( $query );
			$row = $rows [0];
			$kid = $row->keyword_id;
			$start = $row->keyword_start;
			
			if ($start == 0)
				$start = 1;
				
				if ($start == - 1) {
					
					echo '<- exhausted keyword';
					
					if (! in_array ( 'OPT_AE_CACHE', $camp_opt )) {
						$start = 1;
						echo '<br>Cache disabled resetting index to 1';
					} else {
						
						// check if it is reactivated or still deactivated
						if ($this->is_deactivated ( $camp->camp_id, $keyword )) {
							$start = 1;
						} else {
							// still deactivated
							return false;
						}
					}
				} else {
					
					if (! in_array ( 'OPT_AE_CACHE', $camp_opt )) {
						$start = 1;
						echo '<br>Cache disabled resetting index to 1';
					}
				}
				
				echo ' index:' . $start;
				
				// update start index to start+1
				$nextstart = $start + 1;
				$query = "update {$this->wp_prefix}automatic_keywords set keyword_start = $nextstart where keyword_id=$kid ";
				$this->db->query ( $query );
				
				// pagination
				if ( $start == 1 ) {
					
					echo ' Posting from the first page...';
				} else {
					
					// not first page get the bookmark
					$wp_tiktok_next_max_id = get_post_meta ( $camp->camp_id, 'wp_tiktok_next_max_id' . md5 ( $keyword ), 1 );
					
					if (wp_automatic_trim( $wp_tiktok_next_max_id ) == '') {
						echo '<br>No new page max id';
						$wp_tiktok_next_max_id = 0;
					} else {
						if (in_array ( 'OPT_IT_CACHE', $camp_opt )) {
							echo '<br>max_id:' . $wp_tiktok_next_max_id;
						} else {
							$start = 1;
							echo '<br>Cache disabled resetting index to 1';
							$wp_tiktok_next_max_id = 0;
						}
					}
				}
				
			 
				$aliexpress_encoded_keyword = urlencode(wp_automatic_trim($keyword));

				if(in_array('OPT_ALIEXPRESS_CUSTOM' , $camp_opt)){
					
					//custom search link 
					$cg_ae_custom_urls = $camp_general['cg_ae_custom_urls'];
					
					//$aliexpress_url = wp_automatic_str_replace( '[keyword]' , urlencode(wp_automatic_trim($keyword)) , $cg_ae_custom_urls );
					
					$aliexpress_url_parts = explode('aliexpress.com' , $aliexpress_url );
					$aliexpress_domain = wp_automatic_trim($aliexpress_url_parts[0]) . 'aliexpress.com';
					
				}else{
					// prepare keyword https://www.aliexpress.com/af/search.html?SearchText=red+duck
					//$aliexpress_url = 'https://www.aliexpress.com/af/search.html?SearchText=' . urlencode(wp_automatic_trim($keyword)) ;
					
					// new search URL https://www.aliexpress.com/w/wholesale-pizza-box.html?catId=0&initiative_id=SB_20230718094010&SearchText=pizza+box&spm=a2g0o.productlist.1000002.0
					// short fom https://www.aliexpress.com/w/wholesale-pizza-box.html?SearchText=pizza+box
					$aliexpress_domain = 'https://www.aliexpress.com';
					
					//create an initiative_id like SB_20230718094010
					$initiative_id = 'SB_' . date('YmdHis');
 
					//$aliexpress_url = 'https://www.aliexpress.com/w/wholesale-' . $aliexpress_encoded_keyword . '.html?SearchText=' . $aliexpress_encoded_keyword;
					$aliexpress_url = 'https://www.aliexpress.com/w/wholesale-'. $aliexpress_encoded_keyword .'.html?SearchText='. $aliexpress_encoded_keyword . '&catId=0&initiative_id='.$initiative_id.'&spm=a2g0o.productlist.1000002.0&trafficChannel=main&g=y';					
				
				}
			 
				//custom country domain name  
				if(in_array('OPT_ALIEXPRESS_DOMAIN' , $camp_opt)){
					$cg_ae_custom_domain = wp_automatic_trim($camp_general['cg_ae_custom_domain']);
					
					if(stristr($cg_ae_custom_domain, 'aliexpress.com')){
						echo '<br>Custom country/domain is requested: ' . $cg_ae_custom_domain;
						$cg_ae_custom_domain = preg_replace('!/$!' , '' , $cg_ae_custom_domain);
						$aliexpress_url = wp_automatic_str_replace('https://www.aliexpress.com' , $cg_ae_custom_domain , $aliexpress_url ) ;
						$aliexpress_domain = $cg_ae_custom_domain;
					}
				 	
				}else{
					
					//set to US by default
					$cookie_value = $this->cookie_content('aliexpress');
					
					if( ! stristr(  $cookie_value ,  'site=glo'     )){
						echo ' Found global site not set, let us set it ' ;
						$this->cookie_delete('aliexpress');
						 
						curl_setopt($this->ch,CURLOPT_COOKIE, 'aep_usuc_f=site=glo' );
						
					}else{
						echo ' Site is already set to Glo'  ;
					}
					
				}
				
				
				//pagination
				if($start != 1 ){
					$aliexpress_url.= '&page=' . $start;
				}
				
				//infite or load directly
				if(in_array('OPT_TT_INFINITE' , $camp_opt)){
					
					echo '<br>Loading the items from the added HTML...';
					$exec = $camp_general['cg_tt_html'];
					
				}else{
					
					echo '<br>Loading:' . $aliexpress_url;
					
				 
					$x='error';
					curl_setopt($this->ch, CURLOPT_HTTPGET, 1);
					curl_setopt($this->ch, CURLOPT_URL, wp_automatic_trim($aliexpress_url));
					$exec=curl_exec($this->ch);
					$x=curl_error($this->ch);
					
					curl_setopt_array($this->ch, array(
						CURLOPT_URL => $aliexpress_url,
						CURLOPT_RETURNTRANSFER => true,
						CURLOPT_ENCODING => '',
						CURLOPT_MAXREDIRS => 10,
						CURLOPT_TIMEOUT => 0,
						CURLOPT_FOLLOWLOCATION => true,
						CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
						CURLOPT_CUSTOMREQUEST => 'GET',
						CURLOPT_HTTPHEADER => array(
						  'authority: www.aliexpress.com',
						  'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						  'accept-language: en-US,en;q=0.9,ar;q=0.8',
						  'referer: '. $aliexpress_url,
						  'sec-fetch-dest: document',
						  'sec-fetch-mode: navigate',
						  'sec-fetch-site: same-origin',
						  'sec-fetch-user: ?1',
						  'upgrade-insecure-requests: 1',
						  'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
						),
					  ));
					  
					  $exec = curl_exec($this->ch);
					    
					
				}
				
				
				$items = array();
				 
				// "productId":"1005003141253710"
				if( strpos($exec, '"productId":"') ){
					
					//extract video links
					preg_match_all('{"productId":"(\d*)"}s', $exec, $found_items_matches);
					
					$items_ids = $found_items_matches[1];
					 
					// reverse
					if (in_array ( 'OPT_TT_REVERSE', $camp_opt )) {
						echo '<br>Reversing order';
						 
						$items_ids = array_reverse ( $items_id );
					}
					
					echo '<ol>';
					
					// loop items
					$i = 0;
					foreach ( $items_ids as $item ) {
						
						
						
						// clean itm
						unset ( $itm );
						
						
						
						// build item
						$itm ['item_id'] = $item;
						$itm ['item_url'] = "{$aliexpress_domain}/item/" . $item . ".html";
						 
						$data = base64_encode ( serialize ( $itm ) );
						
						$i ++;
						
						echo '<li>' . $itm ['item_url'] . '</li>';
						
						if (! $this->is_duplicate ( $itm ['item_url'] )) {
							$query = "INSERT INTO {$this->wp_prefix}automatic_general ( item_id , item_status , item_data ,item_type) values (    '{$itm['item_id']}', '0', '$data' ,'ae_{$camp->camp_id}_$keyword')  ";
							$this->db->query ( $query );
						} else {
							echo ' <- duplicated <a href="' . get_edit_post_link ( $this->duplicate_id ) . '">#' . $this->duplicate_id . '</a>';
						}
						
						echo '</li>';
					}
					
					echo '</ol>';
					
					echo '<br>Total ' . $i . ' products found & cached';
					
					// check if nothing found so deactivate
					if ($i == 0) {
						echo '<br>No new items got found ';
						echo '<br>Keyword have no more items deactivating...';
						$query = "update {$this->wp_prefix}automatic_keywords set keyword_start = -1 where keyword_id=$kid ";
						$this->db->query ( $query );
						
						if (! in_array ( 'OPT_NO_DEACTIVATE', $camp_opt ))
							$this->deactivate_key ( $camp->camp_id, $keyword );
							 
							
					   } else {
						
					   	//we got products
 
					}

				} else {
					
					// no valid reply
					echo '<br>No Valid reply for AliExpress search '  ;

					echo '<br>Reply: ' . $exec;
					exit;
					
					echo '<br>No new items got found ';
					echo '<br>Keyword have no more items deactivating...';
					$query = "update {$this->wp_prefix}automatic_keywords set keyword_start = -1 where keyword_id=$kid ";
					$this->db->query ( $query );
					
					if (! in_array ( 'OPT_NO_DEACTIVATE', $camp_opt ))
						$this->deactivate_key ( $camp->camp_id, $keyword );
					
				}
	}
	
	function get_numberic_price( $text_price){
		
		$item_price_current = $text_price;
		$item_price_current_pts = explode('-' , $item_price_current );
		$item_price_current = $item_price_current_pts[0];
		
		preg_match('![\d\.\,]+!' , $item_price_current , $price_matchs);
		if(  isset($price_matchs[0]) ){
			return $price_matchs[0];
		}else{
				return '';
			}
		
	}
	
}
