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

#define MTU 512


static unsigned int switch_hook_forward(
    unsigned int hook,
    struct sk_buff *skb,
    const struct net_device *dev_in,
    const struct net_device *dev_out,
    int (*okfn)(struct sk_buff *)
) {
    unsigned int result = NF_ACCEPT;
    struct iphdr *ip_header = ip_hdr(skb);

    if (ip_header->protocol == IPPROTO_TCP) {
        unsigned int ip_header_length = ip_hdrlen(skb);
        unsigned int ip_packet_length = ntohs(ip_header->tot_len);
        
        if (ip_packet_length > MTU) {
            int unused, remain, length;
            int offset, pstart;
            __be16 morefrag;
            struct sk_buff *skb_frag;
            struct iphdr *ip_header_frag;
            skb_push(skb, ETH_HLEN);

            unused = LL_RESERVED_SPACE(skb->dev);
            remain = skb->len - ETH_HLEN - ip_header_length;
            offset = (ntohs(ip_header->frag_off) & IP_OFFSET) << 3;
            pstart = ETH_HLEN + ip_header_length;
            morefrag = ip_header->frag_off & htons(IP_MF);

            while (remain > 0) {
                length = remain > MTU ? MTU : remain;
                if ((skb_frag = alloc_skb(unused + ETH_HLEN + ip_header_length + length, GFP_ATOMIC)) == NULL) {
                    break;
                }
                skb_frag->dev = skb->dev;
                skb_reserve(skb_frag, unused);
                skb_put(skb_frag, ETH_HLEN + ip_header_length + length);
                skb_frag->mac_header = skb_frag->data;
                skb_frag->network_header = skb_frag->data + ETH_HLEN;
                skb_frag->transport_header = skb_frag->data + ETH_HLEN + ip_header_length;
                skb_copy_from_linear_data(skb, skb_mac_header(skb_frag), ETH_HLEN + ip_header_length);
                skb_copy_bits(skb, pstart, skb_transport_header(skb_frag), length);
                remain = remain - length;

                skb_pull(skb_frag, ETH_HLEN);

                skb_reset_network_header(skb_frag);
                skb_pull(skb_frag, ip_header_length);

                skb_reset_transport_header(skb_frag);
                skb_push(skb_frag, ip_header_length);

                ip_header_frag = ip_hdr(skb_frag);
                ip_header_frag->frag_off = htons(offset >> 3);
                if (remain > 0 || morefrag) {
                    ip_header_frag->frag_off = ip_header_frag->frag_off | htons(IP_MF);
                }

                ip_header_frag->frag_off = ip_header_frag->frag_off | htons(IP_DF);
                ip_header_frag->tot_len  = htons(ip_header_length + length);
                ip_header_frag->protocol = IPPROTO_TCP;
                ip_send_check(ip_header_frag);
                skb_push(skb_frag, ETH_HLEN);

                dev_queue_xmit(skb_frag);
                pstart = pstart + length;
                offset = offset + length;
            }
            skb_pull(skb, ETH_HLEN);
            result = NF_DROP;
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
    printk("[packetsplitter] init\n");

    if (nf_register_hooks(switch_hooks, 
                        ARRAY_SIZE(switch_hooks)) 
                        < 0 ) {
            printk("[packetsplitter] register hooks: failure\n");
        } else {
            printk("[packetsplitter] register hooks: success\n");
        }
    return 0;
}

static void switch_exit(void) {
    nf_unregister_hooks(
        switch_hooks,
        ARRAY_SIZE(switch_hooks)
    );
    printk("[packetsplitter] exit\n");
}

module_init(switch_init);
module_exit(switch_exit);

MODULE_AUTHOR("Ahmed Khalil"); 
MODULE_LICENSE("GPL-2.0+");
