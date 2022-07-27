# Notes for Debugging an Incorrectly Inferred Type.


## Initial Issue

Actual initial issue, in the binary for the heap example a usage of the following struct
```c
/* Define the linked list structure.  This is used to link free blocks in order
of their memory address. */
typedef struct A_BLOCK_LINK
{
	struct A_BLOCK_LINK *pxNextFreeBlock;	/*<< The next free block in the list. */
	size_t xBlockSize;						/*<< The size of the free block. */
} BlockLink_t;

```

Gets inferred as:
```c
struct struct_for_node_18
{
	struct struct_for_node_18 *field_at_0;
    struct struct_for_node_18 *field_at_8;
}
```

The second field is accidently unified.


## Narrowing the Scope

The first thing to check is where this unfification between the field @8 and @0 is occuring. After checking the sketches before attempts to bind polymorphic variables for each function
I found the following graph of sub_00003a98 (malloc):
![a sketch showing that node 5 has both a @8 pointer and @0 pointer](./resources/%20before_polybind_sub_00003a98.svg)

So ok that node 13 looks suspicous... there is a recursive edge both from @8 and @0... looks like the integer field got unified into the pointer field. Lets look at the labeling of the nodes to see which DTVs are represented by 13

```
loop_breaker159.store:1
glb_00004030_DAT_00004030.load:9
loop_breaker162:6
loop_breaker23.load.σ64@0.load:1
glb_00004048_DAT_00004048.store:14
loop_breaker156.σ64@0:13
glb_00004048_DAT_00004048.load.σ64@0:12
loop_breaker158:13
glb_00004010_DAT_00004010:8
glb_00004018_DAT_00004018.store.σ64@0:13
loop_breaker160.load.σ64@0:13
loop_breaker24.load:1
loop_breaker156:1
glb_00004018_DAT_00004018:13
loop_breaker27.σ64@0:13
glb_00004010_DAT_00004010.store:4
glb_00004028_DAT_00004028.store:5
loop_breaker161:13
loop_breaker160:13
loop_breaker160.store.σ64@0:13
sub_00003a98.out_0:7
glb_00004000_DAT_00004000.load:3
loop_breaker23.load:1
glb_00004010_DAT_00004010.load:4
glb_00004030_DAT_00004030:2
sub_00003c9c:blk_00003ab8:17
sub_00003dc0:blk_00003be4:15
loop_breaker160.store:1
glb_00004000_DAT_00004000.load.σ64@0:13
loop_breaker24.store:1
glb_00004048_DAT_00004048.load:14
loop_breaker23.store:1
loop_breaker28.load:1
glb_00004028_DAT_00004028.store.σ64@0:12
glb_00004010_DAT_00004010.load.σ64@0:12
loop_breaker157:13
glb_00004018_DAT_00004018.store.σ64@0.store:1
loop_breaker158.store:1
loop_breaker23.load.σ64@0:13
glb_00004028_DAT_00004028:0
sub_00003c9c:blk_00003ab8.out_0:13
loop_breaker159.load.σ64@0:13
glb_001e8470_DAT_001e8470:12
loop_breaker158.load:1
loop_breaker25.σ64@0:13
loop_breaker160.load:1
loop_breaker24:13
sub_00003dc0:blk_00003be4.out_0:13
glb_001ec4b0_DAT_001ec4b0:13
loop_breaker158.store.σ64@8:13
glb_00004048_DAT_00004048.store.σ64@0:12
loop_breaker159.store.σ64@0:13
glb_00004048_DAT_00004048:11
glb_00004000_DAT_00004000:10
glb_00004018_DAT_00004018.store:1
loop_breaker158.load.σ64@0:13
glb_00004000_DAT_00004000.store.σ64@0:13
loop_breaker25:1
loop_breaker160.store.σ64@8:13
loop_breaker155:13
loop_breaker159:13
loop_breaker29.load:1
glb_00004018_DAT_00004018.store.σ64@0.store.σ64@0:13
loop_breaker26.σ64@0:13
loop_breaker158.store.σ64@0:13
glb_00004040_DAT_00004040.store.σ64@0:13
glb_00004018_DAT_00004018.load:1
glb_00004000_DAT_00004000.store:3
loop_breaker23.load.σ64@8:13
loop_breaker24.store.σ64@0:13
sub_00003a98.in_0:13
loop_breaker29:13
sub_00003dc0:blk_00003be4.in_0:13
glb_00004030_DAT_00004030.load.σ64@0:6
loop_breaker28:13
weak_integer:13
loop_breaker159.load:1
glb_00004018_DAT_00004018.load.σ64@0:13
glb_00004040_DAT_00004040.store:1
glb_00004040_DAT_00004040:13
sub_00003a98:16
glb_00004010_DAT_00004010.store.σ64@0:12
loop_breaker26:1
loop_breaker27:1
glb_00004000_DAT_00004000.load.σ64@0.load:1
loop_breaker159.store.σ64@8:13
loop_breaker23:13
loop_breaker24.load.σ64@8:13
loop_breaker23.store.σ64@0:13
```

Huh that's a lot of recursive types bound to 5. The global linked list heads are here so that's good we know they are the same types...

The global types look a little off lets re which variable each one is:
 has:

* DAT_00004000 is a `BlockLink_t*` and is pxEnd
* DAT_00004008 is xBlockAllocatedBit `size_t`
* DAT_00004010 is xFreeBytesRemaining `size_t`
* DAT_00004018 is xStart `BlockLink_t` this means DAT_00004020 is the size field of xstart
* DAT_00004028 is xMinimumEverFreeBytesRemaining `size_t`
* DAT_00004030 is xNumberOfSuccessfulAllocations `size_t`
* DAT_00004038 is xNumberOfSuccessfulFrees `size_t`
* Shaky but the only thing i can imagine is (DAT_00004040+DAT_00004048) is a `BlockLink_t` where &DAT_00004040 is `pxFirstFreeBlock`
In heap:

*  DAT_001ec4b0 + DAT_001ec4b8: `BlockLink_t` is *pxEnd (the last block)
*  DAT_001e8470 well ok i think 001e8470 is the (uxAddress -  ( size_t ) pxFirstFreeBlock) so this is the size of the heap, there is no global there. just the size of the heap minus the size of the block.
Important to remember when we consider a global we insert a variable for the address so the variable glb_00004000 is actually a `BlockLink_t**` since it is a pointer to pxEnd

Ok grepping for globals associated with node 13 (node 13 should be a `BlockLink_t*` ish) and node 1 should be `BlockLink_t`

So:
```
glb_00004018_DAT_00004018.store.σ64@0:13 # So ok we have BlockLink_t* and we go store to that address at field 0 a 64 bit value a BlockLink_t*, makes sense
glb_00004018_DAT_00004018:13 # 4018 is a BlockLink_t* so fine.
glb_00004000_DAT_00004000.load.σ64@0:13 # 4000 is a BlockLink_t* and we go and load from field 0 a 64 bit value at it so this is it's next pointer a BlockLink_t*
glb_001ec4b0_DAT_001ec4b0:13 # this is the address of pxEnd so the type is BlockLink_t*... fine 
glb_00004000_DAT_00004000.store.σ64@0:13 # This is a BlockLink_t* and we go store a 64 bit value to the 0 offset of the pointer so we would be putting a BlockLink_t* there, fine
glb_00004018_DAT_00004018.store.σ64@0.store.σ64@0:13 # Ok 418.store@0 is a BlockLink_t* so if we go and store there at @0 we should also have a BlockLink_t*... fine
glb_00004040_DAT_00004040.store.σ64@0:13 # ok so we decided 4040 was a BlockLink_t*  so go store at offset 0 a 64 bit value, shoudl be a BlockLink_t*... fine
glb_00004018_DAT_00004018.load.σ64@0:13 # ok so 418 is a BlockLink_t* so load at 0 should be fine.
glb_00004040_DAT_00004040:13 # 4040 is a pointer to a BlockLink_t fine
``` 

nothing looks suspciously unified here insofar as the globals are concerned. We may have to dig into the loopbreakers and check provenance over what types they represent but first lets check node 1 as well just for completeness to see if that's where they weird unification happened

Ok so here are the node 1 values, node 1 is supposed to be a `BlockLink_t`

```
glb_00004018_DAT_00004018.store.σ64@0.store:1 # 00004018 is a BlockLink_t* and we do a store (BlockLink_t) then get the field at 0 which is a BlockLink_t* then do a store to get a BlockLink_t... fine
glb_00004018_DAT_00004018.store:1 # 4018 is a BlockLink_t* then we do a store BlockLink_t
glb_00004018_DAT_00004018.load:1 # 4018 is a BlockLink_t* then we do a load BlockLink_t
glb_00004040_DAT_00004040.store:1 # 4040 is a BlockLink_t* then we do a store BlockLink_t
glb_00004000_DAT_00004000.load.σ64@0.load:1 4000 is a BlockLink_t** so we do a load BlockLink_t*, field 0 of a BlockLink_t* is just a noop here, then we load and get a BlockLink_t fine
```

alright so the global caps look fine... probably in the loopbreakers tbh. So ok lets look at the loopbreakers that have an @8, hopefully they are at 13 since that would make sense with what we are seeing.

```
loop_breaker158.store.σ64@8:13
loop_breaker160.store.σ64@8:13
loop_breaker23.load.σ64@8:13
loop_breaker159.store.σ64@8:13
loop_breaker24.load.σ64@8:13
```

Indeed. So the question is what is causing loop_breaker{x}.{load/store}.σ64@8:13 to get unified with BlockLink_t* Lets dive into the constraints on these variables.

So ok here are the @8 constraints
```
sub_00003a98.in_0 ⊑ loop_breaker158.store.σ64@8
sub_00003a98.in_0 ⊑ loop_breaker159.store.σ64@8
sub_00003a98.in_0 ⊑ loop_breaker160.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker158.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker159.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker160.store.σ64@8
sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker158.store.σ64@8
sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker159.store.σ64@8
sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker160.store.σ64@8
```

So ok a constraint like this kinda makes sense: sub_00003a98.in_0 ⊑ loop_breaker158.store.σ64@8. in_0 is the size_t that is the malloc size so as long as loop_breaker158 is a BlockLink_t* we should be ok. loop_breaker158:13 is a mapping so hodl off on this... maybe lets look if there any constraints on that out. We know that the prvInsertBlockIntoFreeList doesnt actually return anything, maybe out_0 causes something to be unified somewhere?

Hmm only thing different is this constraint here:
```
sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker161
```
Lets see if this could propogate somewhere

```
sub_00003a98.in_0 ⊑ loop_breaker161
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker161
sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker161
```
hmm ok so somehow loop_breaker161 is quotiented in  at 13 with in_0 and all the *s. These definitely shouldnt be in this group... why are they.

```
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker158.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker159.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker160.store.σ64@8
sub_00003c9c:blk_00003ab8.out_0 ⊑ loop_breaker161
```
herm these direct unions just have size_ts. Ok maybe what ill do is implement some sort of instrumentation thing that checks when two groups of a certain property are merged so i can track down why they were merged, this assumes ofc that they are starting quotiented in seperate groups... lets see if thats the case.

## Implementing a Debugging Tool To Track Unficiations

So ok scc constraint generation collects a set of simplified constraints we need to insert ourselves into sketch building.

This happens in the `SCCSketchesBuilder` build function, before building the super graph.

So for each scc we call `build_and_label_scc_sketch` which is going to build up that graph. We will copy in external variables as needed.

So the SCCBuilder dispatches to `SketchBuilder` and calls `build_and_label_constraints`

`add_nodes_and_initial_edges` builds the original graph, then generate_quotient_groups quotients it.

So ok after implementing this, they are unioned in the initial group like this:

```
{ sub_00003a98.in_0,loop_breaker158.store.σ64@8,loop_breaker159.store.σ64@8,loop_breaker160.store.σ64@8,loop_breaker161,sub_00003c9c:blk_00003ab8.out_0,glb_00004000_DAT_00004000.load.σ64@0,glb_00004000_DAT_00004000.store.σ64@0,glb_00004018_DAT_00004018,glb_00004018_DAT_00004018.store.σ64@0.store.σ64@0,glb_00004040_DAT_00004040.store.σ64@0,glb_001ec4b0_DAT_001ec4b0,loop_breaker42,loop_breaker42.load.σ64@0,loop_breaker42.store.σ64@0,loop_breaker43,loop_breaker43.store.σ64@0,loop_breaker44.σ64@0,loop_breaker45.σ64@0,loop_breaker46.σ64@0,loop_breaker47,loop_breaker48,sub_00003dc0:blk_00003be4.in_0,sub_00003dc0:blk_00003be4.out_0 }
```
glb_00004018_DAT_00004018 is unioned with sub_00003a98.in_0
which isnt correct, let's figure out what constraint causes them to get unioned


Looks like the quotient comes up from a constraint in sub_00003dc0
Precisely what happens here is 

`sub_00003dc0:blk_00003be4.out_0 ⊑ loop_breaker158.store.σ64@8 50:36`
the out 3dc0 unifies with the 8 field of lb158. The 8 field is the int.

So lets see what out_0 is initially bound to

```
entry_fresh_definition354 ⊑ instr_00003a98_0_sp.store.σ64@40
sub_00003a98.in_0 ⊑ entry_fresh_definition354
sub_00003c9c:blk_00003ab8.out_0 ⊑ entry_fresh_definition354
sub_00003dc0:blk_00003be4.out_0 ⊑ entry_fresh_definition354
```
Ok so the problem fully materializes here:
```
sub_00003dc0:blk_00003be4.out_0 ⊑ entry_fresh_definition354
sub_00003a98.in_0 ⊑ entry_fresh_definition354

instr_00003c18_1_x0 ⊑ sub_00003dc0:blk_00003be4.in_0
τ134.load.σ64@16 ⊑ instr_00003c18_1_x0

aand sub_00003dc0:blk_00003be4.in_0 ⊑ sub_00003dc0:blk_00003be4.out_0
```

Since in_0 of 3dc0 is a BlockLink_t* then sub_00003dc0:blk_00003be4.out_0 becomes unified with BlockLink_t*. since sub_00003a98.in_0 is transitively in the same group as out_0 3dc0 by entry_fresh_definition354 then in_0  of sub_00003a98 gets made into BlockLink_t* but it's a size_t!


So ok why would sub_00003dc0:blk_00003be4.out_0 ⊑ entry_fresh_definition354 get generated for

So alright the full problem is this: so param_1 is in x0 and ghidra thinks g has a return in x0. This leads us to infer the in parameter of g is a subtype of the out parameter of g, which is technically accurate (if we consider x0 as an out param since it’s never written)
f(size_t param_1):
if (unresolvable_condition) {
x0=ptr_to_linked_list
x0=call_g(x0)
}
return_blk:
do stuff unrelated to x0
The problem has to do with how return constraints are generated. Currently, we track all reaching definitions to the return blk of the out param. So in this case it’s going to be both the x0 return from g  and param_1. Since they both get considered as actual return types, they get joined causing the linked list to get joined with the size_t param 1.
I dont really remember why i used the abstract value reaching the return_blk and not the abstract value after the procedures return….i have to think more about wether this would be an acceptable fix
9:58
i dont see an issue with it


ah ok i remember the trick is we want the post condition of the call_return block. which is why we fast forward to the returned to block, but that’s a problem, because that block is going to be the join of the post condition for this block and any other possible preconditions
10:01
So unfortunately I probably have to special case fast forwarding the block to the post condition, that should solve the problem tho (edited) 