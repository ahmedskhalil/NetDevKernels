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


static unsigned int switch_hook_forward(
    unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *dev_in,
    const struct net_device *dev_out,
    int (*okfn)(struct sk_buff *)
) {
    unsigned int result = NF_ACCEPT;
    struct ethhdr *eth_header = eth_hdr(skb);

    switch (ntohs(eth_header->h_proto)) {
        // 1 : IP
        case ETH_P_IP:;
            struct iphdr *ip_header = ip_hdr(skb);
            switch (ntohs(ip_header->protocol))
            {
                case IPPROTO_ICMP:
                break;

                case IPPROTO_UDP:
                // result = NF_DROP;
                break;

                case IPPROTO_ESP:
                result = NF_DROP;
                break;

                case IPPROTO_AH:
                break;
            }
        break;

        // 2 : ARP
        case ETH_P_ARP:
        break;

        // 3 : PPPoE
        case ETH_P_PPP_SES:
        break;
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
