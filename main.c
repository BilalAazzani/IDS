#include "populate.h"
#include <stdbool.h>
#include <syslog.h>
#include <stdlib.h>

struct ids_rule
{
        char protocol[10];
        int source_port;
        int destination_port;
        char source_ip[IP_ADDR_LEN_STR];
        char destination_ip[IP_ADDR_LEN_STR];
        
        char content[255];
        char msg[255];
} typedef Rule;

/*
*
* https://stackoverflow.com/questions/1734507/passing-an-argument-on-libpcap-pcap-loop-callback
*
*/
typedef struct
{
        Rule*rules;
        int number;
} Configuration;


bool check_protocole(Rule* rule,int transport_protocol, char* application_protocol){
        if(strcmp(rule->protocol,"tcp")==0){
                return transport_protocol==1;
        }
        else if (strcmp(rule->protocol,"udp")==0){
                return transport_protocol==2;
        }
        else if (strcmp(rule->protocol,"ftp")==0){
                return strcmp(application_protocol,"ftp")==0;
        }
        else if (strcmp(rule->protocol,"dhcp")==0){
                return strcmp(application_protocol,"dhcp")==0;
        }
        return false;
}

bool check_source_ip(Rule* rule,char* source_ip){
        if(strcmp(rule->source_ip,"any")==0){
                return true;
        }
        else{
                return (strcmp(rule->source_ip,source_ip)==0);
        }
}

bool check_destination_ip(Rule* rule,char* destination_ip){
        if(strcmp(rule->destination_ip,"any")==0){
                return true;
        }
        else{
                return (strcmp(rule->destination_ip,destination_ip)==0);
        }
}

bool check_source_port(Rule* rule,int source_port){
        if(rule->source_port==0){
                return true;
        }
        else{
                return rule->source_port == source_port;
        }
}

bool check_destination_port(Rule* rule,int destination_port){
        if(rule->destination_port==0){
                return true;
        }
        else{
                return rule->destination_port == destination_port;
        }
}

bool check_content(Rule* rule, char* payload){
        if(strlen(rule->content) > 0){
                return strstr(payload,rule->content);
        }
        else{
                return true;
        }
}



void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count)
{
        //Find protocols used in the frame
        int transport_protocol = 1;
        char* application_protocol;
	char* payload_content; 
	char* source_ip = frame->data.source_ip;
	char* destination_ip = frame->data.destination_ip;
	int source_port;
	int destination_port;
	
        if(strcmp(frame->data.transport_protocol,"tcp")==0){
                transport_protocol = 1;
		source_port = frame->data.data.source_port;
		destination_port = frame->data.data.destination_port;

                payload_content = frame->data.data.data;

                if(strstr("220 (vsFTPd ",frame->data.data.data) && (frame->data.data.source_port ==20 || frame->data.data.destination_port == 20 || frame->data.data.source_port == 21 || frame->data.data.destination_port == 21)){
                        application_protocol="ftp";
                }
                else{
                        application_protocol="Unknown";
                }
        }
        else if(strcmp(frame->data.transport_protocol,"udp")==0){
                transport_protocol = 2;
		source_port = frame->data.data_udp.source_port;
		destination_port = frame->data.data_udp.destination_port;

                payload_content = frame->data.data_udp.data;

                if(strstr("DHCP",frame->data.data_udp.data) && (frame->data.data_udp.source_port == 67 || frame->data.data_udp.destination_port == 67 || frame->data.data_udp.source_port == 68 || frame->data.data_udp.destination_port == 68)){
                        application_protocol="dhcp";
                }
                else{
                        application_protocol="Unknown";
                }
		
        }
	else {
		transport_protocol=-1;
		source_port=-1;
		destination_port=-1;
		application_protocol="Unknown";
		payload_content = "Unknown";			

	}
        

        //Loop through the rules to find if there is one that match the frame
        for(int i = 0; i<count; i++){
                Rule* rule = &rules_ds[i];
                if(check_protocole(rule,transport_protocol,application_protocol) 
                && check_source_ip(rule,source_ip) 
                && check_destination_ip(rule,destination_ip)
                && check_source_port(rule,source_port) 
                && check_destination_port(rule,destination_port)
                && check_content(rule,payload_content)){
                        syslog(LOG_ALERT,rule->msg);
                        return;
                }
        }
}




int number_of_lines(FILE * file){
        int count = 0;
        char *line_buffer = NULL;
        size_t line_buffer_size = 0;
        while(getline(&line_buffer,&line_buffer_size,file)>=0){
                count++;
        }
         /* Free the allocated line buffer */
        free(line_buffer);
        line_buffer = NULL;
        return count;
}

/*
*
* https://riptutorial.com/c/example/8274/get-lines-from-a-file-using-getline-- for reading line of file
* https://stackoverflow.com/questions/4693884/nested-strtok-function-problem-in-c for nested strtok
*
*/
void read_rules(FILE* file, Rule *rules_ds, int count)
{
        char *line_buffer = NULL;
        size_t line_buffer_size = 0;
        ssize_t line_size;
        int c = 0;
        char *end_str;

        /* Loop through until we are done with the file. */
        while ((line_size = getline(&line_buffer,&line_buffer_size,file)) >= 0)
        {       
                Rule* currentRule = &rules_ds[c];
                char *tokens = strtok_r(line_buffer,"()",&end_str);
                
                //First token = alert protocol source_ip source_port -> dest_ip dest_port
                char *end_first_token;

                //Alert
                char *firstPart = strtok_r(tokens," ",&end_first_token);

                //Protocol
                firstPart = strtok_r(NULL," ",&end_first_token);
                strcpy(currentRule->protocol,firstPart);

                //Source_ip
                firstPart = strtok_r(NULL," ",&end_first_token);
                strcpy(currentRule->source_ip,firstPart);

                //Source_port
                firstPart = strtok_r(NULL," ",&end_first_token);
                currentRule->source_port=atoi(firstPart);

                //->
                firstPart = strtok_r(NULL," ",&end_first_token);

                //Dest_ip
                firstPart = strtok_r(NULL," ",&end_first_token);
                strcpy(currentRule->destination_ip,firstPart);

                //Dest_port
                firstPart = strtok_r(NULL," ",&end_first_token);
                currentRule->destination_port=atoi(firstPart);
                
                //Second token = option=content;)
                tokens = strtok_r(NULL,"()",&end_str);
                char *end_second_token;

                char *secondPart = strtok_r(tokens,":;",&end_second_token);

                //Loop in each option
                while(secondPart != NULL){
                        if(strcmp(secondPart,"msg") == 0){
                                secondPart = strtok_r(NULL,":;",&end_second_token);
                                strcpy(currentRule->msg,secondPart);  
                        }else if(strcmp(secondPart,"content") == 0){
                                secondPart = strtok_r(NULL,":;",&end_second_token);
                                strcpy(currentRule->content,secondPart);
                        }else{
                                printf("Option %s not considered !",secondPart);
                        }
                        secondPart = strtok_r(NULL,":;",&end_second_token);
                }
                c++;
        }
         /* Free the allocated line buffer */
        free(line_buffer);
        line_buffer = NULL;

        /* Close the file now that we are done with it */
        fclose(file);
}

void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)
{
        Configuration* c = (Configuration*) args;
        ETHER_Frame frame;

        populate_packet_ds(header,packet,&frame);

        rule_matcher(c->rules,&frame,c->number);
}

int main(int argc, char *argv[]) 
{
	printf("Packet analysis in progress ...\n");

        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        //User gives input
        char* interface;
        char* file;
        if(argc > 1){
                file = argv[1];
        }
        else{
                file = "ids.rules";
        }
        interface = "eth1";

        handle = pcap_create(interface,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 0;
        
        FILE *fp = fopen(file,"r");

        int count = number_of_lines(fp);
        rewind(fp);

        Rule *rules = malloc(count*sizeof(Rule));
        //Initialization of the rules structure
        for(int i=0; i<count; i++){
                Rule* currentRule = &rules[i];
                strcpy(currentRule->content,"");
        }

        read_rules(fp,rules,count);

        
        
        //Declaration of a structure to pass both parameters to pcap_loop function
        Configuration c = {rules,count};

        pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*)&c);

        free(rules);
        //https://stackoverflow.com/questions/53312543/why-does-valgrind-report-a-memory-leak-when-calling-pcap-open-offline
        pcap_close(handle);
        return 0;
}
