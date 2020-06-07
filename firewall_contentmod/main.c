/*
 * -*- mode: c++; c-basic-offset: 2; indent-tabs-mode: 4; -*-
 * Author        : Ahmed Khalil
 * Created       : 15.05.20
 * 
 * Licensed under the GNU Affero License AGPL, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://www.gnu.org/licenses/agpl-3.0.en.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/ip.h>


void tcp_checksum(struct sk_buff *skb) {
    if (skb_is_nonlinear(skb)) skb_linearize(skb);

    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    unsigned int tcp_header_len = (skb->len - (ip_header->ihl << 2));

    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(
        tcp_header_len,
        ip_header->saddr,
        ip_header->daddr,
        csum_partial(
            (char*)tcp_header,
            tcp_header_len,
            0
        )
    );
    skb->ip_summed = CHECKSUM_NONE;
}



static unsigned int switch_hook_forward(
    unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *dev_in,
    const struct net_device *dev_out,
    int (*okfn)(struct sk_buff *)
) {
    unsigned int result = NF_ACCEPT;
    struct ethhdr *eth_header = eth_hdr(skb);

    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        struct iphdr *ip_header = ip_hdr(skb);
        unsigned int ip_header_length = ip_hdrlen(skb);
        unsigned int ip_packet_length = ntohs(ip_header->tot_len);
        unsigned char *payload = (unsigned char *)ip_header 
                                    + ip_header_length;
        int i;
        for (i = 0; i < ip_packet_length - ip_header_length - 6; i++) {
            unsigned char byte_0 = *(payload + i + 0);
            unsigned char byte_1 = *(payload + i + 1);
            unsigned char byte_2 = *(payload + i + 2);
            unsigned char byte_3 = *(payload + i + 3);
            unsigned char byte_4 = *(payload + i + 4);
            unsigned char byte_5 = *(payload + i + 5);
            if (byte_0 == 'j' && 
                byte_1 == 'u' && 
                byte_2 == 'n' && 
                byte_3 == 'g' && 
                byte_4 == 'u' && 
                byte_5 == 'n') {
                    *(payload + i + 0) = 'h';
                    *(payload + i + 0) = 'i';
                    *(payload + i + 0) = 'l';
                    *(payload + i + 0) = 'a';
                    *(payload + i + 0) = 'r';
                    *(payload + i + 0) = 'y';
                }
        }
    }
   
    return result;
}


static struct nf_hook_ops switch_hooks[] __read_mostly = {{
    .hook       = switch_hook_forward,
    .owner      = THIS_MODULE,
    .pf         = NFPROTO_BRIDGE,
    .hooknum    = NF_BR_FORWARD,
    .priority   = NF_BR_PRI_FILTER_BRIDGED,
}};

static int __init switch_init(void) {
    printk("[switch] init\n");

    if (nf_register_hooks(switch_hooks, 
                        ARRAY_SIZE(switch_hooks)) 
                        < 0 ) {
            printk("[switch] register hooks: failure\n");
        } else {
            printk("[switch] register hooks: success\n");
        }
    return 0;
}

static void switch_exit(void) {
    nf_unregister_hooks(
        switch_hooks,
        ARRAY_SIZE(switch_hooks)
    );
    printk("[switch] exit\n");
}

module_init(switch_init);
module_exit(switch_exit);

MODULE_AUTHOR("Ahmed Khalil"); 
MODULE_LICENSE("GPL-2.0+");
