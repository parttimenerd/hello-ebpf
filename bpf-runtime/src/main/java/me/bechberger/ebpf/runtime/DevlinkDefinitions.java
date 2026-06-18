/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with devlink
 */
@java.lang.SuppressWarnings("unused")
public final class DevlinkDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_compat_running_version(Ptr<devlink> devlink, String buf,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_flash_update_notify(Ptr<devlink> devlink, devlink_command cmd,
      Ptr<devlink_flash_notify> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devlink_health_reporter_create($arg1, (const struct devlink_health_reporter_ops*)$arg2, $arg3, $arg4)")
  public static Ptr<devlink_health_reporter> __devlink_health_reporter_create(Ptr<devlink> devlink,
      Ptr<devlink_health_reporter_ops> ops, @Unsigned long graceful_period, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devlink_port_phys_port_name_get(Ptr<devlink_port> devlink_port, String name,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_port_type_set(Ptr<devlink_port> devlink_port, devlink_port_type type,
      Ptr<?> type_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devlink_region_snapshot_create(Ptr<devlink_region> region,
      Ptr<java.lang.Character> data, @Unsigned int snapshot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_rel_put(Ptr<devlink_rel> rel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_reload_stats_update(Ptr<devlink> devlink,
      Ptr<java.lang. @Unsigned Integer> reload_stats, devlink_reload_limit limit,
      @Unsigned int actions_performed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devlink_snapshot_id_decrement(Ptr<devlink> devlink, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devlink_trap_action_set(Ptr<devlink> devlink,
      Ptr<devlink_trap_item> trap_item, devlink_trap_action trap_action,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_add_symlinks(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_alloc_ns((const struct devlink_ops*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<devlink> devlink_alloc_ns(Ptr<devlink_ops> ops, @Unsigned long priv_size,
      Ptr<net> net, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_attr_param_type_validate((const struct nlattr*)$arg1, $arg2)")
  public static int devlink_attr_param_type_validate(Ptr<nlattr> attr,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_class_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_compat_flash_update($arg1, (const u8*)$arg2)")
  public static int devlink_compat_flash_update(Ptr<devlink> devlink, String file_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_compat_phys_port_name_get(Ptr<net_device> dev, String name,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_compat_running_version(Ptr<devlink> devlink, String buf,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_compat_switch_id_get(Ptr<net_device> dev,
      Ptr<netdev_phys_item_id> ppid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_action_put(Ptr<sk_buff> skb, Ptr<devlink_dpipe_action> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_dpipe_entry_clear(Ptr<devlink_dpipe_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_entry_ctx_append(Ptr<devlink_dpipe_dump_ctx> dump_ctx,
      Ptr<devlink_dpipe_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_entry_ctx_close(Ptr<devlink_dpipe_dump_ctx> dump_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_entry_ctx_prepare(Ptr<devlink_dpipe_dump_ctx> dump_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_entry_put(Ptr<sk_buff> skb, Ptr<devlink_dpipe_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_match_put(Ptr<sk_buff> skb, Ptr<devlink_dpipe_match> match) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_send_and_alloc_skb(Ptr<Ptr<sk_buff>> pskb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_dpipe_table_counter_enabled($arg1, (const u8*)$arg2)")
  public static boolean devlink_dpipe_table_counter_enabled(Ptr<devlink> devlink,
      String table_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_table_put(Ptr<sk_buff> skb, Ptr<devlink_dpipe_table> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_dpipe_value_put(Ptr<sk_buff> skb, Ptr<devlink_dpipe_value> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_flash_component_lookup_cb((const u8*)$arg1, $arg2, $arg3)")
  public static void devlink_flash_component_lookup_cb(String version_name,
      devlink_info_version_type version_type, Ptr<?> version_cb_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_flash_update_status_notify($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void devlink_flash_update_status_notify(Ptr<devlink> devlink, String status_msg,
      String component, @Unsigned long done, @Unsigned long total) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_flash_update_timeout_notify($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4)")
  public static void devlink_flash_update_timeout_notify(Ptr<devlink> devlink, String status_msg,
      String component, @Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_arr_pair_nest_end(Ptr<devlink_fmsg> fmsg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_arr_pair_nest_start($arg1, (const u8*)$arg2)")
  public static void devlink_fmsg_arr_pair_nest_start(Ptr<devlink_fmsg> fmsg, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_binary_pair_nest_end(Ptr<devlink_fmsg> fmsg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_binary_pair_nest_start($arg1, (const u8*)$arg2)")
  public static void devlink_fmsg_binary_pair_nest_start(Ptr<devlink_fmsg> fmsg, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_binary_pair_put($arg1, (const u8*)$arg2, (const void*)$arg3, $arg4)")
  public static void devlink_fmsg_binary_pair_put(Ptr<devlink_fmsg> fmsg, String name, Ptr<?> value,
      @Unsigned int value_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_binary_put($arg1, (const void*)$arg2, $arg3)")
  public static void devlink_fmsg_binary_put(Ptr<devlink_fmsg> fmsg, Ptr<?> value,
      @Unsigned short value_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_bool_pair_put($arg1, (const u8*)$arg2, $arg3)")
  public static void devlink_fmsg_bool_pair_put(Ptr<devlink_fmsg> fmsg, String name,
      boolean value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_dump_skb($arg1, (const struct sk_buff*)$arg2)")
  public static void devlink_fmsg_dump_skb(Ptr<devlink_fmsg> fmsg, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_nest_common(Ptr<devlink_fmsg> fmsg, int attrtype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_obj_nest_end(Ptr<devlink_fmsg> fmsg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_obj_nest_start(Ptr<devlink_fmsg> fmsg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_pair_nest_end(Ptr<devlink_fmsg> fmsg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_pair_nest_start($arg1, (const u8*)$arg2)")
  public static void devlink_fmsg_pair_nest_start(Ptr<devlink_fmsg> fmsg, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_fmsg_prepare_skb(Ptr<devlink_fmsg> fmsg, Ptr<sk_buff> skb,
      Ptr<java.lang.Integer> start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_put_name($arg1, (const u8*)$arg2)")
  public static void devlink_fmsg_put_name(Ptr<devlink_fmsg> fmsg, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_put_value($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static void devlink_fmsg_put_value(Ptr<devlink_fmsg> fmsg, Ptr<?> value,
      @Unsigned short value_len, char value_nla_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_string_pair_put($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static void devlink_fmsg_string_pair_put(Ptr<devlink_fmsg> fmsg, String name,
      String value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_string_put($arg1, (const u8*)$arg2)")
  public static void devlink_fmsg_string_put(Ptr<devlink_fmsg> fmsg, String value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_u32_pair_put($arg1, (const u8*)$arg2, $arg3)")
  public static void devlink_fmsg_u32_pair_put(Ptr<devlink_fmsg> fmsg, String name,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_fmsg_u32_put(Ptr<devlink_fmsg> fmsg, @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_u64_pair_put($arg1, (const u8*)$arg2, $arg3)")
  public static void devlink_fmsg_u64_pair_put(Ptr<devlink_fmsg> fmsg, String name,
      @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_fmsg_u8_pair_put($arg1, (const u8*)$arg2, $arg3)")
  public static void devlink_fmsg_u8_pair_put(Ptr<devlink_fmsg> fmsg, String name, char value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_free(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink> devlink_get_from_attrs_lock(Ptr<net> net, Ptr<Ptr<nlattr>> attrs,
      boolean dev_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_health_do_dump(Ptr<devlink_health_reporter> reporter, Ptr<?> priv_ctx,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_health_report($arg1, (const u8*)$arg2, $arg3)")
  public static int devlink_health_report(Ptr<devlink_health_reporter> reporter, String msg,
      Ptr<?> priv_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_health_reporter_create($arg1, (const struct devlink_health_reporter_ops*)$arg2, $arg3, $arg4)")
  public static Ptr<devlink_health_reporter> devlink_health_reporter_create(Ptr<devlink> devlink,
      Ptr<devlink_health_reporter_ops> ops, @Unsigned long graceful_period, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_health_reporter_destroy(Ptr<devlink_health_reporter> reporter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_health_reporter> devlink_health_reporter_get_from_attrs(
      Ptr<devlink> devlink, Ptr<Ptr<nlattr>> attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devlink_health_reporter_priv(Ptr<devlink_health_reporter> reporter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_health_reporter_recover(Ptr<devlink_health_reporter> reporter,
      Ptr<?> priv_ctx, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_health_reporter_recovery_done(Ptr<devlink_health_reporter> reporter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_health_reporter_state_update(Ptr<devlink_health_reporter> reporter,
      devlink_health_reporter_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_board_serial_number_put($arg1, (const u8*)$arg2)")
  public static int devlink_info_board_serial_number_put(Ptr<devlink_info_req> req, String bsn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_serial_number_put($arg1, (const u8*)$arg2)")
  public static int devlink_info_serial_number_put(Ptr<devlink_info_req> req, String sn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_fixed_put($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static int devlink_info_version_fixed_put(Ptr<devlink_info_req> req, String version_name,
      String version_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_put($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4, $arg5)")
  public static int devlink_info_version_put(Ptr<devlink_info_req> req, int attr,
      String version_name, String version_value, devlink_info_version_type version_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_running_put($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static int devlink_info_version_running_put(Ptr<devlink_info_req> req, String version_name,
      String version_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_running_put_ext($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4)")
  public static int devlink_info_version_running_put_ext(Ptr<devlink_info_req> req,
      String version_name, String version_value, devlink_info_version_type version_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_stored_put($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static int devlink_info_version_stored_put(Ptr<devlink_info_req> req, String version_name,
      String version_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_info_version_stored_put_ext($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4)")
  public static int devlink_info_version_stored_put_ext(Ptr<devlink_info_req> req,
      String version_name, String version_value, devlink_info_version_type version_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_is_reload_failed((const struct devlink*)$arg1)")
  public static boolean devlink_is_reload_failed(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_activate(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_deactivate(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int devlink_linecard_index(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_linecard_nested_dl_set(Ptr<devlink_linecard> linecard,
      Ptr<devlink> nested_devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_notify(Ptr<devlink_linecard> linecard, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_provision_clear(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_provision_fail(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_linecard_provision_set($arg1, (const u8*)$arg2)")
  public static void devlink_linecard_provision_set(Ptr<devlink_linecard> linecard, String type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_rel_cleanup_cb(Ptr<devlink> devlink,
      @Unsigned int linecard_index, @Unsigned int rel_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecard_rel_notify_cb(Ptr<devlink> devlink,
      @Unsigned int linecard_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_linecard_type_set($arg1, (const u8*)$arg2, $arg3)")
  public static int devlink_linecard_type_set(Ptr<devlink_linecard> linecard, String type,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_linecard_types_init(Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecards_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_linecards_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_net((const struct devlink*)$arg1)")
  public static Ptr<net> devlink_net(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_dpipe_entries_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_dpipe_headers_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_dpipe_table_counters_set_doit(Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_dpipe_table_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_dumpit(Ptr<sk_buff> msg, Ptr<netlink_callback> cb, Ptr<?> dump_one) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_eswitch_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_eswitch_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink, devlink_command cmd,
      @Unsigned int portid, @Unsigned int seq, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_flash_update_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_flash_update_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      devlink_command cmd, Ptr<devlink_flash_notify> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_get_dumpit(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_diagnose_doit(Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_dump_clear_doit(Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_dump_get_dumpit(Ptr<sk_buff> skb,
      Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_fill(Ptr<sk_buff> msg,
      Ptr<devlink_health_reporter> reporter, devlink_command cmd, @Unsigned int portid,
      @Unsigned int seq, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_get_dumpit(Ptr<sk_buff> skb,
      Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_recover_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_health_reporter_test_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_info_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_info_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_info_get_dumpit(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_linecard_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<devlink_linecard> linecard, devlink_command cmd, @Unsigned int portid, @Unsigned int seq,
      int flags, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_linecard_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_linecard_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_linecard_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_linecard_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_msg_reply_and_new(Ptr<Ptr<sk_buff>> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_notify_filter(Ptr<sock> dsk, Ptr<sk_buff> skb, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_notify_filter_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_param_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_param_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_param_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_param_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_param_value_fill_one(Ptr<sk_buff> msg, devlink_param_type type,
      devlink_param_cmode cmode, devlink_param_value val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_attrs_put(Ptr<sk_buff> msg, Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_del_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_fill(Ptr<sk_buff> msg, Ptr<devlink_port> devlink_port,
      devlink_command cmd, @Unsigned int portid, @Unsigned int seq, int flags,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_function_attrs_put(Ptr<sk_buff> msg, Ptr<devlink_port> port,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_handle_fill(Ptr<sk_buff> msg, Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long devlink_nl_port_handle_size(Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_new_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_param_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_param_get_dumpit(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_param_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_split_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_port_unsplit_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void devlink_nl_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_post_doit_dev_lock((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void devlink_nl_post_doit_dev_lock(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int devlink_nl_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_pre_doit_dev_lock((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int devlink_nl_pre_doit_dev_lock(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_pre_doit_port((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int devlink_nl_pre_doit_port(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_pre_doit_port_optional((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int devlink_nl_pre_doit_port_optional(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_put_handle(Ptr<sk_buff> msg, Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_put_nested_handle(Ptr<sk_buff> msg, Ptr<net> net,
      Ptr<devlink> devlink, int attrtype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_del_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_fill(Ptr<sk_buff> msg, Ptr<devlink_rate> devlink_rate,
      devlink_command cmd, @Unsigned int portid, @Unsigned int seq, int flags,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_new_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_parent_node_set(Ptr<devlink_rate> devlink_rate,
      Ptr<genl_info> info, Ptr<nlattr> nla_parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_rate_set($arg1, (const struct devlink_ops*)$arg2, $arg3)")
  public static int devlink_nl_rate_set(Ptr<devlink_rate> devlink_rate, Ptr<devlink_ops> ops,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_rate_tc_bw_set(Ptr<devlink_rate> devlink_rate, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_del_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_new_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_nl_region_notify(Ptr<devlink_region> region,
      Ptr<devlink_snapshot> snapshot, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> devlink_nl_region_notify_build(Ptr<devlink_region> region,
      Ptr<devlink_snapshot> snapshot, devlink_command cmd, @Unsigned int portid,
      @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_region_read_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_reload_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_resource_dump_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_resource_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_occ_max_clear_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_occ_snapshot_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_pool_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_pool_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_pool_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_pool_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_port_pool_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_port_pool_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_port_pool_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_port_pool_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_tc_pool_bind_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_tc_pool_bind_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_tc_pool_bind_get_dumpit(Ptr<sk_buff> skb,
      Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_sb_tc_pool_bind_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_selftests_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      @Unsigned int portid, @Unsigned int seq, int flags, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_selftests_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_selftests_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_selftests_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_selftests_run_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_nl_sock_priv_destroy(Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_nl_sock_priv_init(Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_trap_fill($arg1, $arg2, (const struct devlink_trap_item*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int devlink_nl_trap_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<devlink_trap_item> trap_item, devlink_command cmd, @Unsigned int portid,
      @Unsigned int seq, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_trap_group_fill($arg1, $arg2, (const struct devlink_trap_group_item*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int devlink_nl_trap_group_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<devlink_trap_group_item> group_item, devlink_command cmd, @Unsigned int portid,
      @Unsigned int seq, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_group_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_group_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_group_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_group_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_nl_trap_policer_fill($arg1, $arg2, (const struct devlink_trap_policer_item*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int devlink_nl_trap_policer_fill(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<devlink_trap_policer_item> policer_item, devlink_command cmd, @Unsigned int portid,
      @Unsigned int seq, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_policer_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_policer_get_dump_one(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      Ptr<netlink_callback> cb, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_policer_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_policer_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_nl_trap_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_notify(Ptr<devlink> devlink, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_param_cmode_is_supported((const struct devlink_param*)$arg1, $arg2)")
  public static boolean devlink_param_cmode_is_supported(Ptr<devlink_param> param,
      devlink_param_cmode cmode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_param_find_by_name($arg1, (const u8*)$arg2)")
  public static Ptr<devlink_param_item> devlink_param_find_by_name(Ptr<xarray> params,
      String param_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_param_register($arg1, (const struct devlink_param*)$arg2)")
  public static int devlink_param_register(Ptr<devlink> devlink, Ptr<devlink_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_param_unregister($arg1, (const struct devlink_param*)$arg2)")
  public static void devlink_param_unregister(Ptr<devlink> devlink, Ptr<devlink_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_params_driverinit_load_new(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_params_notify(Ptr<devlink> devlink, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_params_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_params_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_params_register($arg1, (const struct devlink_param*)$arg2, $arg3)")
  public static int devlink_params_register(Ptr<devlink> devlink, Ptr<devlink_param> params,
      @Unsigned long params_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_params_unregister($arg1, (const struct devlink_param*)$arg2, $arg3)")
  public static void devlink_params_unregister(Ptr<devlink> devlink, Ptr<devlink_param> params,
      @Unsigned long params_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_pernet_pre_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_attrs_pci_pf_set(Ptr<devlink_port> devlink_port,
      @Unsigned int controller, @Unsigned short pf, boolean external) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_attrs_pci_sf_set(Ptr<devlink_port> devlink_port,
      @Unsigned int controller, @Unsigned short pf, @Unsigned int sf, boolean external) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_attrs_pci_vf_set(Ptr<devlink_port> devlink_port,
      @Unsigned int controller, @Unsigned short pf, @Unsigned short vf, boolean external) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_attrs_set(Ptr<devlink_port> devlink_port,
      Ptr<devlink_port_attrs> attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_fini(Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_port_fn_caps_fill(Ptr<devlink_port> devlink_port, Ptr<sk_buff> msg,
      Ptr<netlink_ext_ack> extack, Ptr<java.lang. @OriginalName("bool") Boolean> msg_updated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_port_function_set($arg1, (const struct nlattr*)$arg2, $arg3)")
  public static int devlink_port_function_set(Ptr<devlink_port> port, Ptr<nlattr> attr,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_port_function_validate(Ptr<devlink_port> devlink_port,
      Ptr<Ptr<nlattr>> tb, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_port> devlink_port_get_by_index(Ptr<devlink> devlink,
      @Unsigned int port_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_port> devlink_port_get_from_attrs(Ptr<devlink> devlink,
      Ptr<Ptr<nlattr>> attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_port> devlink_port_get_from_info(Ptr<devlink> devlink,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_port_health_reporter_create($arg1, (const struct devlink_health_reporter_ops*)$arg2, $arg3, $arg4)")
  public static Ptr<devlink_health_reporter> devlink_port_health_reporter_create(
      Ptr<devlink_port> port, Ptr<devlink_health_reporter_ops> ops, @Unsigned long graceful_period,
      Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_init(Ptr<devlink> devlink, Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_linecard_set(Ptr<devlink_port> devlink_port,
      Ptr<devlink_linecard> linecard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_port_netdevice_event(Ptr<notifier_block> nb, @Unsigned long event,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_notify(Ptr<devlink_port> devlink_port, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_port_region_create($arg1, (const struct devlink_port_region_ops*)$arg2, $arg3, $arg4)")
  public static Ptr<devlink_region> devlink_port_region_create(Ptr<devlink_port> port,
      Ptr<devlink_port_region_ops> ops, @Unsigned int region_max_snapshots,
      @Unsigned long region_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_port_register_with_ops($arg1, $arg2, $arg3, (const struct devlink_port_ops*)$arg4)")
  public static int devlink_port_register_with_ops(Ptr<devlink> devlink,
      Ptr<devlink_port> devlink_port, @Unsigned int port_index, Ptr<devlink_port_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_rel_cleanup_cb(Ptr<devlink> devlink, @Unsigned int port_index,
      @Unsigned int rel_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_rel_notify_cb(Ptr<devlink> devlink, @Unsigned int port_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_type_clear(Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_type_eth_set(Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_type_ib_set(Ptr<devlink_port> devlink_port,
      Ptr<ib_device> ibdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_type_warn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_port_unregister(Ptr<devlink_port> devlink_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_ports_notify(Ptr<devlink> devlink, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_ports_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_ports_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devlink_priv(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_put(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_rate> devlink_rate_get_from_info(Ptr<devlink> devlink,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_rate> devlink_rate_node_get_from_attrs(Ptr<devlink> devlink,
      Ptr<Ptr<nlattr>> attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_rate_nodes_check(Ptr<devlink> devlink, @Unsigned short mode,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rate_notify(Ptr<devlink_rate> devlink_rate, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_rate_set_ops_supported((const struct devlink_ops*)$arg1, $arg2, $arg3)")
  public static boolean devlink_rate_set_ops_supported(Ptr<devlink_ops> ops, Ptr<genl_info> info,
      devlink_rate_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rates_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rates_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_recover_notify(Ptr<devlink_health_reporter> reporter,
      devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_region_create($arg1, (const struct devlink_region_ops*)$arg2, $arg3, $arg4)")
  public static Ptr<devlink_region> devlink_region_create(Ptr<devlink> devlink,
      Ptr<devlink_region_ops> ops, @Unsigned int region_max_snapshots, @Unsigned long region_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_region_destroy(Ptr<devlink_region> region) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_region_direct_fill(Ptr<?> cb_priv, Ptr<java.lang.Character> chunk,
      @Unsigned int chunk_size, @Unsigned long curr_offset, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_region_port_direct_fill(Ptr<?> cb_priv, Ptr<java.lang.Character> chunk,
      @Unsigned int chunk_size, @Unsigned long curr_offset, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_region_snapshot_create(Ptr<devlink_region> region,
      Ptr<java.lang.Character> data, @Unsigned int snapshot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_region_snapshot_del(Ptr<devlink_region> region,
      Ptr<devlink_snapshot> snapshot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_region_snapshot_fill(Ptr<?> cb_priv, Ptr<java.lang.Character> chunk,
      @Unsigned int chunk_size, @Unsigned long curr_offset, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_region_snapshot_id_get(Ptr<devlink> devlink,
      Ptr<java.lang. @Unsigned Integer> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_region_snapshot_id_put(Ptr<devlink> devlink, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_regions_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_regions_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_cleanup_cb(Ptr<devlink> devlink, @Unsigned int obj_index,
      @Unsigned int rel_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_rel_devlink_handle_put(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      @Unsigned int rel_index, int attrtype,
      Ptr<java.lang. @OriginalName("bool") Boolean> msg_updated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_rel_nested_in_add(Ptr<java.lang. @Unsigned Integer> rel_index,
      @Unsigned int devlink_index, @Unsigned int obj_index, Ptr<?> notify_cb, Ptr<?> cleanup_cb,
      Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_nested_in_clear(@Unsigned int rel_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_nested_in_notify(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_nested_in_notify_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_nested_in_notify_work_schedule(Ptr<devlink_rel> rel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_rel_notify_cb(Ptr<devlink> devlink, @Unsigned int obj_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_release(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_reload(Ptr<devlink> devlink, Ptr<net> dest_net,
      devlink_reload_action action, devlink_reload_limit limit,
      Ptr<java.lang. @Unsigned Integer> actions_performed, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean devlink_reload_action_is_supported(Ptr<devlink> devlink,
      devlink_reload_action action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_reload_actions_valid((const struct devlink_ops*)$arg1)")
  public static boolean devlink_reload_actions_valid(Ptr<devlink_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean devlink_reload_limit_is_supported(Ptr<devlink> devlink,
      devlink_reload_limit limit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_reload_stats_put(Ptr<sk_buff> msg, Ptr<devlink> devlink,
      boolean is_remote) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_remote_reload_actions_performed(Ptr<devlink> devlink,
      devlink_reload_limit limit, @Unsigned int actions_performed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_remove_symlinks(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink_resource> devlink_resource_find(Ptr<devlink> devlink,
      Ptr<devlink_resource> resource, @Unsigned long resource_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_resources_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_resources_validate(Ptr<devlink> devlink, Ptr<devlink_resource> resource,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devlink_sb_register(Ptr<devlink> devlink, @Unsigned int sb_index,
      @Unsigned int size, @Unsigned short ingress_pools_count, @Unsigned short egress_pools_count,
      @Unsigned short ingress_tc_count, @Unsigned short egress_tc_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_sb_unregister(Ptr<devlink> devlink, @Unsigned int sb_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_to_dev((const struct devlink*)$arg1)")
  public static Ptr<device> devlink_to_dev(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devlink_trap_ctx_priv(Ptr<?> trap_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_group_notify($arg1, (const struct devlink_trap_group_item*)$arg2, $arg3)")
  public static void devlink_trap_group_notify(Ptr<devlink> devlink,
      Ptr<devlink_trap_group_item> group_item, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_group_register($arg1, (const struct devlink_trap_group*)$arg2)")
  public static int devlink_trap_group_register(Ptr<devlink> devlink,
      Ptr<devlink_trap_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_group_unregister($arg1, (const struct devlink_trap_group*)$arg2)")
  public static void devlink_trap_group_unregister(Ptr<devlink> devlink,
      Ptr<devlink_trap_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_trap_groups_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_trap_groups_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_groups_register($arg1, (const struct devlink_trap_group*)$arg2, $arg3)")
  public static int devlink_trap_groups_register(Ptr<devlink> devlink,
      Ptr<devlink_trap_group> groups, @Unsigned long groups_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_groups_unregister($arg1, (const struct devlink_trap_group*)$arg2, $arg3)")
  public static void devlink_trap_groups_unregister(Ptr<devlink> devlink,
      Ptr<devlink_trap_group> groups, @Unsigned long groups_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_notify($arg1, (const struct devlink_trap_item*)$arg2, $arg3)")
  public static void devlink_trap_notify(Ptr<devlink> devlink, Ptr<devlink_trap_item> trap_item,
      devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_policer_notify($arg1, (const struct devlink_trap_policer_item*)$arg2, $arg3)")
  public static void devlink_trap_policer_notify(Ptr<devlink> devlink,
      Ptr<devlink_trap_policer_item> policer_item, devlink_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_policer_unregister($arg1, (const struct devlink_trap_policer*)$arg2)")
  public static void devlink_trap_policer_unregister(Ptr<devlink> devlink,
      Ptr<devlink_trap_policer> policer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_trap_policers_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_trap_policers_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_register($arg1, (const struct devlink_trap*)$arg2, $arg3)")
  public static int devlink_trap_register(Ptr<devlink> devlink, Ptr<devlink_trap> trap,
      Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_report($arg1, $arg2, $arg3, $arg4, (const struct flow_action_cookie*)$arg5)")
  public static void devlink_trap_report(Ptr<devlink> devlink, Ptr<sk_buff> skb, Ptr<?> trap_ctx,
      Ptr<devlink_port> in_devlink_port, Ptr<flow_action_cookie> fa_cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_trap_stats_read(Ptr<devlink_stats> trap_stats,
      Ptr<devlink_stats> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_trap_unregister($arg1, (const struct devlink_trap*)$arg2)")
  public static void devlink_trap_unregister(Ptr<devlink> devlink, Ptr<devlink_trap> trap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_traps_notify_register(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_traps_notify_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_traps_register($arg1, (const struct devlink_trap*)$arg2, $arg3, $arg4)")
  public static int devlink_traps_register(Ptr<devlink> devlink, Ptr<devlink_trap> traps,
      @Unsigned long traps_count, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devlink_traps_unregister($arg1, (const struct devlink_trap*)$arg2, $arg3)")
  public static void devlink_traps_unregister(Ptr<devlink> devlink, Ptr<devlink_trap> traps,
      @Unsigned long traps_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devlink> devlink_try_get(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devlink_unregister(Ptr<devlink> devlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port extends Struct {
    public list_head list;

    public list_head region_list;

    public Ptr<devlink> devlink;

    public Ptr<devlink_port_ops> ops;

    public @Unsigned int index;

    public @OriginalName("spinlock_t") spinlock type_lock;

    public devlink_port_type type;

    public devlink_port_type desired_type;

    @InlineUnion(57595)
    public type_eth_of_anon_member_of_devlink_port type_eth;

    @InlineUnion(57595)
    public type_ib_of_anon_member_of_devlink_port type_ib;

    public devlink_port_attrs attrs;

    public char attrs_set;

    public char switch_port;

    public char registered;

    public char initialized;

    public delayed_work type_warn_dw;

    public list_head reporter_list;

    public Ptr<devlink_rate> devlink_rate;

    public Ptr<devlink_linecard> linecard;

    public @Unsigned int rel_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_type"
  )
  public enum devlink_port_type implements Enum<devlink_port_type>, TypedEnum<devlink_port_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_TYPE_NOTSET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_TYPE_NOTSET"
    )
    DEVLINK_PORT_TYPE_NOTSET,

    /**
     * {@code DEVLINK_PORT_TYPE_AUTO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_TYPE_AUTO"
    )
    DEVLINK_PORT_TYPE_AUTO,

    /**
     * {@code DEVLINK_PORT_TYPE_ETH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PORT_TYPE_ETH"
    )
    DEVLINK_PORT_TYPE_ETH,

    /**
     * {@code DEVLINK_PORT_TYPE_IB = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PORT_TYPE_IB"
    )
    DEVLINK_PORT_TYPE_IB
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_sb_pool_type"
  )
  public enum devlink_sb_pool_type implements Enum<devlink_sb_pool_type>, TypedEnum<devlink_sb_pool_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_SB_POOL_TYPE_INGRESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_SB_POOL_TYPE_INGRESS"
    )
    DEVLINK_SB_POOL_TYPE_INGRESS,

    /**
     * {@code DEVLINK_SB_POOL_TYPE_EGRESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_SB_POOL_TYPE_EGRESS"
    )
    DEVLINK_SB_POOL_TYPE_EGRESS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_sb_threshold_type"
  )
  public enum devlink_sb_threshold_type implements Enum<devlink_sb_threshold_type>, TypedEnum<devlink_sb_threshold_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_SB_THRESHOLD_TYPE_STATIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_SB_THRESHOLD_TYPE_STATIC"
    )
    DEVLINK_SB_THRESHOLD_TYPE_STATIC,

    /**
     * {@code DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC"
    )
    DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_flavour"
  )
  public enum devlink_port_flavour implements Enum<devlink_port_flavour>, TypedEnum<devlink_port_flavour, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_FLAVOUR_PHYSICAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_FLAVOUR_PHYSICAL"
    )
    DEVLINK_PORT_FLAVOUR_PHYSICAL,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_CPU = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_FLAVOUR_CPU"
    )
    DEVLINK_PORT_FLAVOUR_CPU,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_DSA = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PORT_FLAVOUR_DSA"
    )
    DEVLINK_PORT_FLAVOUR_DSA,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_PCI_PF = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PORT_FLAVOUR_PCI_PF"
    )
    DEVLINK_PORT_FLAVOUR_PCI_PF,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_PCI_VF = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_PORT_FLAVOUR_PCI_VF"
    )
    DEVLINK_PORT_FLAVOUR_PCI_VF,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_VIRTUAL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_PORT_FLAVOUR_VIRTUAL"
    )
    DEVLINK_PORT_FLAVOUR_VIRTUAL,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_UNUSED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_PORT_FLAVOUR_UNUSED"
    )
    DEVLINK_PORT_FLAVOUR_UNUSED,

    /**
     * {@code DEVLINK_PORT_FLAVOUR_PCI_SF = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_PORT_FLAVOUR_PCI_SF"
    )
    DEVLINK_PORT_FLAVOUR_PCI_SF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_rate_type"
  )
  public enum devlink_rate_type implements Enum<devlink_rate_type>, TypedEnum<devlink_rate_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_RATE_TYPE_LEAF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_RATE_TYPE_LEAF"
    )
    DEVLINK_RATE_TYPE_LEAF,

    /**
     * {@code DEVLINK_RATE_TYPE_NODE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_RATE_TYPE_NODE"
    )
    DEVLINK_RATE_TYPE_NODE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_param_cmode"
  )
  public enum devlink_param_cmode implements Enum<devlink_param_cmode>, TypedEnum<devlink_param_cmode, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PARAM_CMODE_RUNTIME = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PARAM_CMODE_RUNTIME"
    )
    DEVLINK_PARAM_CMODE_RUNTIME,

    /**
     * {@code DEVLINK_PARAM_CMODE_DRIVERINIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PARAM_CMODE_DRIVERINIT"
    )
    DEVLINK_PARAM_CMODE_DRIVERINIT,

    /**
     * {@code DEVLINK_PARAM_CMODE_PERMANENT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PARAM_CMODE_PERMANENT"
    )
    DEVLINK_PARAM_CMODE_PERMANENT,

    /**
     * {@code __DEVLINK_PARAM_CMODE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DEVLINK_PARAM_CMODE_MAX"
    )
    __DEVLINK_PARAM_CMODE_MAX,

    /**
     * {@code DEVLINK_PARAM_CMODE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PARAM_CMODE_MAX"
    )
    DEVLINK_PARAM_CMODE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_fn_state"
  )
  public enum devlink_port_fn_state implements Enum<devlink_port_fn_state>, TypedEnum<devlink_port_fn_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_FN_STATE_INACTIVE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_FN_STATE_INACTIVE"
    )
    DEVLINK_PORT_FN_STATE_INACTIVE,

    /**
     * {@code DEVLINK_PORT_FN_STATE_ACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_FN_STATE_ACTIVE"
    )
    DEVLINK_PORT_FN_STATE_ACTIVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_fn_opstate"
  )
  public enum devlink_port_fn_opstate implements Enum<devlink_port_fn_opstate>, TypedEnum<devlink_port_fn_opstate, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_FN_OPSTATE_DETACHED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_FN_OPSTATE_DETACHED"
    )
    DEVLINK_PORT_FN_OPSTATE_DETACHED,

    /**
     * {@code DEVLINK_PORT_FN_OPSTATE_ATTACHED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_FN_OPSTATE_ATTACHED"
    )
    DEVLINK_PORT_FN_OPSTATE_ATTACHED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_phys_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_phys_attrs extends Struct {
    public @Unsigned int port_number;

    public @Unsigned int split_subport_number;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_pci_pf_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_pci_pf_attrs extends Struct {
    public @Unsigned int controller;

    public @Unsigned short pf;

    public char external;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_pci_vf_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_pci_vf_attrs extends Struct {
    public @Unsigned int controller;

    public @Unsigned short pf;

    public @Unsigned short vf;

    public char external;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_pci_sf_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_pci_sf_attrs extends Struct {
    public @Unsigned int controller;

    public @Unsigned int sf;

    public @Unsigned short pf;

    public char external;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_attrs extends Struct {
    public char split;

    public char splittable;

    public char no_phys_port_name;

    public @Unsigned int lanes;

    public devlink_port_flavour flavour;

    public netdev_phys_item_id switch_id;

    @InlineUnion(57586)
    public devlink_port_phys_attrs phys;

    @InlineUnion(57586)
    public devlink_port_pci_pf_attrs pci_pf;

    @InlineUnion(57586)
    public devlink_port_pci_vf_attrs pci_vf;

    @InlineUnion(57586)
    public devlink_port_pci_sf_attrs pci_sf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_rate"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_rate extends Struct {
    public list_head list;

    public devlink_rate_type type;

    public Ptr<devlink> devlink;

    public Ptr<?> priv;

    public @Unsigned long tx_share;

    public @Unsigned long tx_max;

    public Ptr<devlink_rate> parent;

    @InlineUnion(57589)
    public Ptr<devlink_port> devlink_port;

    @InlineUnion(57589)
    public anon_member_of_anon_member_of_devlink_rate anon7$1;

    public @Unsigned int tx_priority;

    public @Unsigned int tx_weight;

    public @Unsigned int @Size(8) [] tc_bw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_ops extends Struct {
    public Ptr<?> port_split;

    public Ptr<?> port_unsplit;

    public Ptr<?> port_type_set;

    public Ptr<?> port_del;

    public Ptr<?> port_fn_hw_addr_get;

    public Ptr<?> port_fn_hw_addr_set;

    public Ptr<?> port_fn_roce_get;

    public Ptr<?> port_fn_roce_set;

    public Ptr<?> port_fn_migratable_get;

    public Ptr<?> port_fn_migratable_set;

    public Ptr<?> port_fn_state_get;

    public Ptr<?> port_fn_state_set;

    public Ptr<?> port_fn_ipsec_crypto_get;

    public Ptr<?> port_fn_ipsec_crypto_set;

    public Ptr<?> port_fn_ipsec_packet_get;

    public Ptr<?> port_fn_ipsec_packet_set;

    public Ptr<?> port_fn_max_io_eqs_get;

    public Ptr<?> port_fn_max_io_eqs_set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_sb_pool_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_sb_pool_info extends Struct {
    public devlink_sb_pool_type pool_type;

    public @Unsigned int size;

    public devlink_sb_threshold_type threshold_type;

    public @Unsigned int cell_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union devlink_param_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_param_value extends Union {
    public char vu8;

    public @Unsigned short vu16;

    public @Unsigned int vu32;

    public @Unsigned long vu64;

    public char @Size(32) [] vstr;

    public boolean vbool;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_param_gset_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_param_gset_ctx extends Struct {
    public devlink_param_value val;

    public devlink_param_cmode cmode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_trap_type"
  )
  public enum devlink_trap_type implements Enum<devlink_trap_type>, TypedEnum<devlink_trap_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_TRAP_TYPE_DROP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_TRAP_TYPE_DROP"
    )
    DEVLINK_TRAP_TYPE_DROP,

    /**
     * {@code DEVLINK_TRAP_TYPE_EXCEPTION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_TRAP_TYPE_EXCEPTION"
    )
    DEVLINK_TRAP_TYPE_EXCEPTION,

    /**
     * {@code DEVLINK_TRAP_TYPE_CONTROL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_TRAP_TYPE_CONTROL"
    )
    DEVLINK_TRAP_TYPE_CONTROL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_metadata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_metadata extends Struct {
    public String trap_name;

    public String trap_group_name;

    public Ptr<net_device> input_dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public Ptr<flow_action_cookie> fa_cookie;

    public devlink_trap_type trap_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_eswitch_encap_mode"
  )
  public enum devlink_eswitch_encap_mode implements Enum<devlink_eswitch_encap_mode>, TypedEnum<devlink_eswitch_encap_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_ESWITCH_ENCAP_MODE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_ESWITCH_ENCAP_MODE_NONE"
    )
    DEVLINK_ESWITCH_ENCAP_MODE_NONE,

    /**
     * {@code DEVLINK_ESWITCH_ENCAP_MODE_BASIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_ESWITCH_ENCAP_MODE_BASIC"
    )
    DEVLINK_ESWITCH_ENCAP_MODE_BASIC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_attr_selftest_id"
  )
  public enum devlink_attr_selftest_id implements Enum<devlink_attr_selftest_id>, TypedEnum<devlink_attr_selftest_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_ATTR_SELFTEST_ID_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_ATTR_SELFTEST_ID_UNSPEC"
    )
    DEVLINK_ATTR_SELFTEST_ID_UNSPEC,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_ID_FLASH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_ATTR_SELFTEST_ID_FLASH"
    )
    DEVLINK_ATTR_SELFTEST_ID_FLASH,

    /**
     * {@code __DEVLINK_ATTR_SELFTEST_ID_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__DEVLINK_ATTR_SELFTEST_ID_MAX"
    )
    __DEVLINK_ATTR_SELFTEST_ID_MAX,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_ID_MAX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_ATTR_SELFTEST_ID_MAX"
    )
    DEVLINK_ATTR_SELFTEST_ID_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_selftest_status"
  )
  public enum devlink_selftest_status implements Enum<devlink_selftest_status>, TypedEnum<devlink_selftest_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_SELFTEST_STATUS_SKIP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_SELFTEST_STATUS_SKIP"
    )
    DEVLINK_SELFTEST_STATUS_SKIP,

    /**
     * {@code DEVLINK_SELFTEST_STATUS_PASS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_SELFTEST_STATUS_PASS"
    )
    DEVLINK_SELFTEST_STATUS_PASS,

    /**
     * {@code DEVLINK_SELFTEST_STATUS_FAIL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_SELFTEST_STATUS_FAIL"
    )
    DEVLINK_SELFTEST_STATUS_FAIL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_trap_action"
  )
  public enum devlink_trap_action implements Enum<devlink_trap_action>, TypedEnum<devlink_trap_action, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_TRAP_ACTION_DROP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_TRAP_ACTION_DROP"
    )
    DEVLINK_TRAP_ACTION_DROP,

    /**
     * {@code DEVLINK_TRAP_ACTION_TRAP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_TRAP_ACTION_TRAP"
    )
    DEVLINK_TRAP_ACTION_TRAP,

    /**
     * {@code DEVLINK_TRAP_ACTION_MIRROR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_TRAP_ACTION_MIRROR"
    )
    DEVLINK_TRAP_ACTION_MIRROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_reload_action"
  )
  public enum devlink_reload_action implements Enum<devlink_reload_action>, TypedEnum<devlink_reload_action, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_RELOAD_ACTION_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_RELOAD_ACTION_UNSPEC"
    )
    DEVLINK_RELOAD_ACTION_UNSPEC,

    /**
     * {@code DEVLINK_RELOAD_ACTION_DRIVER_REINIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_RELOAD_ACTION_DRIVER_REINIT"
    )
    DEVLINK_RELOAD_ACTION_DRIVER_REINIT,

    /**
     * {@code DEVLINK_RELOAD_ACTION_FW_ACTIVATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_RELOAD_ACTION_FW_ACTIVATE"
    )
    DEVLINK_RELOAD_ACTION_FW_ACTIVATE,

    /**
     * {@code __DEVLINK_RELOAD_ACTION_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DEVLINK_RELOAD_ACTION_MAX"
    )
    __DEVLINK_RELOAD_ACTION_MAX,

    /**
     * {@code DEVLINK_RELOAD_ACTION_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_RELOAD_ACTION_MAX"
    )
    DEVLINK_RELOAD_ACTION_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_reload_limit"
  )
  public enum devlink_reload_limit implements Enum<devlink_reload_limit>, TypedEnum<devlink_reload_limit, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_RELOAD_LIMIT_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_RELOAD_LIMIT_UNSPEC"
    )
    DEVLINK_RELOAD_LIMIT_UNSPEC,

    /**
     * {@code DEVLINK_RELOAD_LIMIT_NO_RESET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_RELOAD_LIMIT_NO_RESET"
    )
    DEVLINK_RELOAD_LIMIT_NO_RESET,

    /**
     * {@code __DEVLINK_RELOAD_LIMIT_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__DEVLINK_RELOAD_LIMIT_MAX"
    )
    __DEVLINK_RELOAD_LIMIT_MAX,

    /**
     * {@code DEVLINK_RELOAD_LIMIT_MAX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_RELOAD_LIMIT_MAX"
    )
    DEVLINK_RELOAD_LIMIT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_rate_tc_attr"
  )
  public enum devlink_rate_tc_attr implements Enum<devlink_rate_tc_attr>, TypedEnum<devlink_rate_tc_attr, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_RATE_TC_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_RATE_TC_ATTR_UNSPEC"
    )
    DEVLINK_RATE_TC_ATTR_UNSPEC,

    /**
     * {@code DEVLINK_RATE_TC_ATTR_INDEX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_RATE_TC_ATTR_INDEX"
    )
    DEVLINK_RATE_TC_ATTR_INDEX,

    /**
     * {@code DEVLINK_RATE_TC_ATTR_BW = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_RATE_TC_ATTR_BW"
    )
    DEVLINK_RATE_TC_ATTR_BW,

    /**
     * {@code __DEVLINK_RATE_TC_ATTR_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DEVLINK_RATE_TC_ATTR_MAX"
    )
    __DEVLINK_RATE_TC_ATTR_MAX,

    /**
     * {@code DEVLINK_RATE_TC_ATTR_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_RATE_TC_ATTR_MAX"
    )
    DEVLINK_RATE_TC_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_field_mapping_type"
  )
  public enum devlink_dpipe_field_mapping_type implements Enum<devlink_dpipe_field_mapping_type>, TypedEnum<devlink_dpipe_field_mapping_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE"
    )
    DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE,

    /**
     * {@code DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX"
    )
    DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_function_attr"
  )
  public enum devlink_port_function_attr implements Enum<devlink_port_function_attr>, TypedEnum<devlink_port_function_attr, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_FUNCTION_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_FUNCTION_ATTR_UNSPEC"
    )
    DEVLINK_PORT_FUNCTION_ATTR_UNSPEC,

    /**
     * {@code DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR"
    )
    DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_STATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PORT_FN_ATTR_STATE"
    )
    DEVLINK_PORT_FN_ATTR_STATE,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_OPSTATE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PORT_FN_ATTR_OPSTATE"
    )
    DEVLINK_PORT_FN_ATTR_OPSTATE,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_CAPS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_PORT_FN_ATTR_CAPS"
    )
    DEVLINK_PORT_FN_ATTR_CAPS,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_DEVLINK = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_PORT_FN_ATTR_DEVLINK"
    )
    DEVLINK_PORT_FN_ATTR_DEVLINK,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_MAX_IO_EQS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_PORT_FN_ATTR_MAX_IO_EQS"
    )
    DEVLINK_PORT_FN_ATTR_MAX_IO_EQS,

    /**
     * {@code __DEVLINK_PORT_FUNCTION_ATTR_MAX = 7}
     */
    @EnumMember(
        value = 7L,
        name = "__DEVLINK_PORT_FUNCTION_ATTR_MAX"
    )
    __DEVLINK_PORT_FUNCTION_ATTR_MAX,

    /**
     * {@code DEVLINK_PORT_FUNCTION_ATTR_MAX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_PORT_FUNCTION_ATTR_MAX"
    )
    DEVLINK_PORT_FUNCTION_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_new_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_new_attrs extends Struct {
    public devlink_port_flavour flavour;

    public @Unsigned int port_index;

    public @Unsigned int controller;

    public @Unsigned int sfnum;

    public @Unsigned short pfnum;

    public char port_index_valid;

    public char controller_valid;

    public char sfnum_valid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_field"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_field extends Struct {
    public String name;

    public @Unsigned int id;

    public @Unsigned int bitwidth;

    public devlink_dpipe_field_mapping_type mapping_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_header extends Struct {
    public String name;

    public @Unsigned int id;

    public Ptr<devlink_dpipe_field> fields;

    public @Unsigned int fields_count;

    public boolean global;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_headers"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_headers extends Struct {
    public Ptr<Ptr<devlink_dpipe_header>> headers;

    public @Unsigned int headers_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_flash_update_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_flash_update_params extends Struct {
    public Ptr<firmware> fw;

    public String component;

    public @Unsigned int overwrite_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_policer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_policer extends Struct {
    public @Unsigned int id;

    public @Unsigned long init_rate;

    public @Unsigned long init_burst;

    public @Unsigned long max_rate;

    public @Unsigned long min_rate;

    public @Unsigned long max_burst;

    public @Unsigned long min_burst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_group extends Struct {
    public String name;

    public @Unsigned short id;

    public boolean generic;

    public @Unsigned int init_policer_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap extends Struct {
    public devlink_trap_type type;

    public devlink_trap_action init_action;

    public boolean generic;

    public @Unsigned short id;

    public String name;

    public @Unsigned short init_group_id;

    public @Unsigned int metadata_cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_ops extends Struct {
    public @Unsigned int supported_flash_update_params;

    public @Unsigned long reload_actions;

    public @Unsigned long reload_limits;

    public Ptr<?> reload_down;

    public Ptr<?> reload_up;

    public Ptr<?> sb_pool_get;

    public Ptr<?> sb_pool_set;

    public Ptr<?> sb_port_pool_get;

    public Ptr<?> sb_port_pool_set;

    public Ptr<?> sb_tc_pool_bind_get;

    public Ptr<?> sb_tc_pool_bind_set;

    public Ptr<?> sb_occ_snapshot;

    public Ptr<?> sb_occ_max_clear;

    public Ptr<?> sb_occ_port_pool_get;

    public Ptr<?> sb_occ_tc_port_bind_get;

    public Ptr<?> eswitch_mode_get;

    public Ptr<?> eswitch_mode_set;

    public Ptr<?> eswitch_inline_mode_get;

    public Ptr<?> eswitch_inline_mode_set;

    public Ptr<?> eswitch_encap_mode_get;

    public Ptr<?> eswitch_encap_mode_set;

    public Ptr<?> info_get;

    public Ptr<?> flash_update;

    public Ptr<?> trap_init;

    public Ptr<?> trap_fini;

    public Ptr<?> trap_action_set;

    public Ptr<?> trap_group_init;

    public Ptr<?> trap_group_set;

    public Ptr<?> trap_group_action_set;

    public Ptr<?> trap_drop_counter_get;

    public Ptr<?> trap_policer_init;

    public Ptr<?> trap_policer_fini;

    public Ptr<?> trap_policer_set;

    public Ptr<?> trap_policer_counter_get;

    public Ptr<?> port_new;

    public Ptr<?> rate_leaf_tx_share_set;

    public Ptr<?> rate_leaf_tx_max_set;

    public Ptr<?> rate_leaf_tx_priority_set;

    public Ptr<?> rate_leaf_tx_weight_set;

    public Ptr<?> rate_leaf_tc_bw_set;

    public Ptr<?> rate_node_tx_share_set;

    public Ptr<?> rate_node_tx_max_set;

    public Ptr<?> rate_node_tx_priority_set;

    public Ptr<?> rate_node_tx_weight_set;

    public Ptr<?> rate_node_tc_bw_set;

    public Ptr<?> rate_node_new;

    public Ptr<?> rate_node_del;

    public Ptr<?> rate_leaf_parent_set;

    public Ptr<?> rate_node_parent_set;

    public Ptr<?> selftest_check;

    public Ptr<?> selftest_run;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dev_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dev_stats extends Struct {
    public @Unsigned int @Size(6) [] reload_stats;

    public @Unsigned int @Size(6) [] remote_reload_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_rel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_rel extends Struct {
    public @Unsigned int index;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public @Unsigned int devlink_index;

    public nested_in_of_devlink_rel nested_in;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_command"
  )
  public enum devlink_command implements Enum<devlink_command>, TypedEnum<devlink_command, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_CMD_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_CMD_UNSPEC"
    )
    DEVLINK_CMD_UNSPEC,

    /**
     * {@code DEVLINK_CMD_GET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_CMD_GET"
    )
    DEVLINK_CMD_GET,

    /**
     * {@code DEVLINK_CMD_SET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_CMD_SET"
    )
    DEVLINK_CMD_SET,

    /**
     * {@code DEVLINK_CMD_NEW = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_CMD_NEW"
    )
    DEVLINK_CMD_NEW,

    /**
     * {@code DEVLINK_CMD_DEL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_CMD_DEL"
    )
    DEVLINK_CMD_DEL,

    /**
     * {@code DEVLINK_CMD_PORT_GET = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_CMD_PORT_GET"
    )
    DEVLINK_CMD_PORT_GET,

    /**
     * {@code DEVLINK_CMD_PORT_SET = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_CMD_PORT_SET"
    )
    DEVLINK_CMD_PORT_SET,

    /**
     * {@code DEVLINK_CMD_PORT_NEW = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_CMD_PORT_NEW"
    )
    DEVLINK_CMD_PORT_NEW,

    /**
     * {@code DEVLINK_CMD_PORT_DEL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DEVLINK_CMD_PORT_DEL"
    )
    DEVLINK_CMD_PORT_DEL,

    /**
     * {@code DEVLINK_CMD_PORT_SPLIT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DEVLINK_CMD_PORT_SPLIT"
    )
    DEVLINK_CMD_PORT_SPLIT,

    /**
     * {@code DEVLINK_CMD_PORT_UNSPLIT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_CMD_PORT_UNSPLIT"
    )
    DEVLINK_CMD_PORT_UNSPLIT,

    /**
     * {@code DEVLINK_CMD_SB_GET = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_CMD_SB_GET"
    )
    DEVLINK_CMD_SB_GET,

    /**
     * {@code DEVLINK_CMD_SB_SET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DEVLINK_CMD_SB_SET"
    )
    DEVLINK_CMD_SB_SET,

    /**
     * {@code DEVLINK_CMD_SB_NEW = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DEVLINK_CMD_SB_NEW"
    )
    DEVLINK_CMD_SB_NEW,

    /**
     * {@code DEVLINK_CMD_SB_DEL = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DEVLINK_CMD_SB_DEL"
    )
    DEVLINK_CMD_SB_DEL,

    /**
     * {@code DEVLINK_CMD_SB_POOL_GET = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DEVLINK_CMD_SB_POOL_GET"
    )
    DEVLINK_CMD_SB_POOL_GET,

    /**
     * {@code DEVLINK_CMD_SB_POOL_SET = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DEVLINK_CMD_SB_POOL_SET"
    )
    DEVLINK_CMD_SB_POOL_SET,

    /**
     * {@code DEVLINK_CMD_SB_POOL_NEW = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DEVLINK_CMD_SB_POOL_NEW"
    )
    DEVLINK_CMD_SB_POOL_NEW,

    /**
     * {@code DEVLINK_CMD_SB_POOL_DEL = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_CMD_SB_POOL_DEL"
    )
    DEVLINK_CMD_SB_POOL_DEL,

    /**
     * {@code DEVLINK_CMD_SB_PORT_POOL_GET = 19}
     */
    @EnumMember(
        value = 19L,
        name = "DEVLINK_CMD_SB_PORT_POOL_GET"
    )
    DEVLINK_CMD_SB_PORT_POOL_GET,

    /**
     * {@code DEVLINK_CMD_SB_PORT_POOL_SET = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DEVLINK_CMD_SB_PORT_POOL_SET"
    )
    DEVLINK_CMD_SB_PORT_POOL_SET,

    /**
     * {@code DEVLINK_CMD_SB_PORT_POOL_NEW = 21}
     */
    @EnumMember(
        value = 21L,
        name = "DEVLINK_CMD_SB_PORT_POOL_NEW"
    )
    DEVLINK_CMD_SB_PORT_POOL_NEW,

    /**
     * {@code DEVLINK_CMD_SB_PORT_POOL_DEL = 22}
     */
    @EnumMember(
        value = 22L,
        name = "DEVLINK_CMD_SB_PORT_POOL_DEL"
    )
    DEVLINK_CMD_SB_PORT_POOL_DEL,

    /**
     * {@code DEVLINK_CMD_SB_TC_POOL_BIND_GET = 23}
     */
    @EnumMember(
        value = 23L,
        name = "DEVLINK_CMD_SB_TC_POOL_BIND_GET"
    )
    DEVLINK_CMD_SB_TC_POOL_BIND_GET,

    /**
     * {@code DEVLINK_CMD_SB_TC_POOL_BIND_SET = 24}
     */
    @EnumMember(
        value = 24L,
        name = "DEVLINK_CMD_SB_TC_POOL_BIND_SET"
    )
    DEVLINK_CMD_SB_TC_POOL_BIND_SET,

    /**
     * {@code DEVLINK_CMD_SB_TC_POOL_BIND_NEW = 25}
     */
    @EnumMember(
        value = 25L,
        name = "DEVLINK_CMD_SB_TC_POOL_BIND_NEW"
    )
    DEVLINK_CMD_SB_TC_POOL_BIND_NEW,

    /**
     * {@code DEVLINK_CMD_SB_TC_POOL_BIND_DEL = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DEVLINK_CMD_SB_TC_POOL_BIND_DEL"
    )
    DEVLINK_CMD_SB_TC_POOL_BIND_DEL,

    /**
     * {@code DEVLINK_CMD_SB_OCC_SNAPSHOT = 27}
     */
    @EnumMember(
        value = 27L,
        name = "DEVLINK_CMD_SB_OCC_SNAPSHOT"
    )
    DEVLINK_CMD_SB_OCC_SNAPSHOT,

    /**
     * {@code DEVLINK_CMD_SB_OCC_MAX_CLEAR = 28}
     */
    @EnumMember(
        value = 28L,
        name = "DEVLINK_CMD_SB_OCC_MAX_CLEAR"
    )
    DEVLINK_CMD_SB_OCC_MAX_CLEAR,

    /**
     * {@code DEVLINK_CMD_ESWITCH_GET = 29}
     */
    @EnumMember(
        value = 29L,
        name = "DEVLINK_CMD_ESWITCH_GET"
    )
    DEVLINK_CMD_ESWITCH_GET,

    /**
     * {@code DEVLINK_CMD_ESWITCH_SET = 30}
     */
    @EnumMember(
        value = 30L,
        name = "DEVLINK_CMD_ESWITCH_SET"
    )
    DEVLINK_CMD_ESWITCH_SET,

    /**
     * {@code DEVLINK_CMD_DPIPE_TABLE_GET = 31}
     */
    @EnumMember(
        value = 31L,
        name = "DEVLINK_CMD_DPIPE_TABLE_GET"
    )
    DEVLINK_CMD_DPIPE_TABLE_GET,

    /**
     * {@code DEVLINK_CMD_DPIPE_ENTRIES_GET = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DEVLINK_CMD_DPIPE_ENTRIES_GET"
    )
    DEVLINK_CMD_DPIPE_ENTRIES_GET,

    /**
     * {@code DEVLINK_CMD_DPIPE_HEADERS_GET = 33}
     */
    @EnumMember(
        value = 33L,
        name = "DEVLINK_CMD_DPIPE_HEADERS_GET"
    )
    DEVLINK_CMD_DPIPE_HEADERS_GET,

    /**
     * {@code DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET = 34}
     */
    @EnumMember(
        value = 34L,
        name = "DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET"
    )
    DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET,

    /**
     * {@code DEVLINK_CMD_RESOURCE_SET = 35}
     */
    @EnumMember(
        value = 35L,
        name = "DEVLINK_CMD_RESOURCE_SET"
    )
    DEVLINK_CMD_RESOURCE_SET,

    /**
     * {@code DEVLINK_CMD_RESOURCE_DUMP = 36}
     */
    @EnumMember(
        value = 36L,
        name = "DEVLINK_CMD_RESOURCE_DUMP"
    )
    DEVLINK_CMD_RESOURCE_DUMP,

    /**
     * {@code DEVLINK_CMD_RELOAD = 37}
     */
    @EnumMember(
        value = 37L,
        name = "DEVLINK_CMD_RELOAD"
    )
    DEVLINK_CMD_RELOAD,

    /**
     * {@code DEVLINK_CMD_PARAM_GET = 38}
     */
    @EnumMember(
        value = 38L,
        name = "DEVLINK_CMD_PARAM_GET"
    )
    DEVLINK_CMD_PARAM_GET,

    /**
     * {@code DEVLINK_CMD_PARAM_SET = 39}
     */
    @EnumMember(
        value = 39L,
        name = "DEVLINK_CMD_PARAM_SET"
    )
    DEVLINK_CMD_PARAM_SET,

    /**
     * {@code DEVLINK_CMD_PARAM_NEW = 40}
     */
    @EnumMember(
        value = 40L,
        name = "DEVLINK_CMD_PARAM_NEW"
    )
    DEVLINK_CMD_PARAM_NEW,

    /**
     * {@code DEVLINK_CMD_PARAM_DEL = 41}
     */
    @EnumMember(
        value = 41L,
        name = "DEVLINK_CMD_PARAM_DEL"
    )
    DEVLINK_CMD_PARAM_DEL,

    /**
     * {@code DEVLINK_CMD_REGION_GET = 42}
     */
    @EnumMember(
        value = 42L,
        name = "DEVLINK_CMD_REGION_GET"
    )
    DEVLINK_CMD_REGION_GET,

    /**
     * {@code DEVLINK_CMD_REGION_SET = 43}
     */
    @EnumMember(
        value = 43L,
        name = "DEVLINK_CMD_REGION_SET"
    )
    DEVLINK_CMD_REGION_SET,

    /**
     * {@code DEVLINK_CMD_REGION_NEW = 44}
     */
    @EnumMember(
        value = 44L,
        name = "DEVLINK_CMD_REGION_NEW"
    )
    DEVLINK_CMD_REGION_NEW,

    /**
     * {@code DEVLINK_CMD_REGION_DEL = 45}
     */
    @EnumMember(
        value = 45L,
        name = "DEVLINK_CMD_REGION_DEL"
    )
    DEVLINK_CMD_REGION_DEL,

    /**
     * {@code DEVLINK_CMD_REGION_READ = 46}
     */
    @EnumMember(
        value = 46L,
        name = "DEVLINK_CMD_REGION_READ"
    )
    DEVLINK_CMD_REGION_READ,

    /**
     * {@code DEVLINK_CMD_PORT_PARAM_GET = 47}
     */
    @EnumMember(
        value = 47L,
        name = "DEVLINK_CMD_PORT_PARAM_GET"
    )
    DEVLINK_CMD_PORT_PARAM_GET,

    /**
     * {@code DEVLINK_CMD_PORT_PARAM_SET = 48}
     */
    @EnumMember(
        value = 48L,
        name = "DEVLINK_CMD_PORT_PARAM_SET"
    )
    DEVLINK_CMD_PORT_PARAM_SET,

    /**
     * {@code DEVLINK_CMD_PORT_PARAM_NEW = 49}
     */
    @EnumMember(
        value = 49L,
        name = "DEVLINK_CMD_PORT_PARAM_NEW"
    )
    DEVLINK_CMD_PORT_PARAM_NEW,

    /**
     * {@code DEVLINK_CMD_PORT_PARAM_DEL = 50}
     */
    @EnumMember(
        value = 50L,
        name = "DEVLINK_CMD_PORT_PARAM_DEL"
    )
    DEVLINK_CMD_PORT_PARAM_DEL,

    /**
     * {@code DEVLINK_CMD_INFO_GET = 51}
     */
    @EnumMember(
        value = 51L,
        name = "DEVLINK_CMD_INFO_GET"
    )
    DEVLINK_CMD_INFO_GET,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_GET = 52}
     */
    @EnumMember(
        value = 52L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_GET"
    )
    DEVLINK_CMD_HEALTH_REPORTER_GET,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_SET = 53}
     */
    @EnumMember(
        value = 53L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_SET"
    )
    DEVLINK_CMD_HEALTH_REPORTER_SET,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_RECOVER = 54}
     */
    @EnumMember(
        value = 54L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_RECOVER"
    )
    DEVLINK_CMD_HEALTH_REPORTER_RECOVER,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE = 55}
     */
    @EnumMember(
        value = 55L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE"
    )
    DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET = 56}
     */
    @EnumMember(
        value = 56L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET"
    )
    DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR = 57}
     */
    @EnumMember(
        value = 57L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR"
    )
    DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR,

    /**
     * {@code DEVLINK_CMD_FLASH_UPDATE = 58}
     */
    @EnumMember(
        value = 58L,
        name = "DEVLINK_CMD_FLASH_UPDATE"
    )
    DEVLINK_CMD_FLASH_UPDATE,

    /**
     * {@code DEVLINK_CMD_FLASH_UPDATE_END = 59}
     */
    @EnumMember(
        value = 59L,
        name = "DEVLINK_CMD_FLASH_UPDATE_END"
    )
    DEVLINK_CMD_FLASH_UPDATE_END,

    /**
     * {@code DEVLINK_CMD_FLASH_UPDATE_STATUS = 60}
     */
    @EnumMember(
        value = 60L,
        name = "DEVLINK_CMD_FLASH_UPDATE_STATUS"
    )
    DEVLINK_CMD_FLASH_UPDATE_STATUS,

    /**
     * {@code DEVLINK_CMD_TRAP_GET = 61}
     */
    @EnumMember(
        value = 61L,
        name = "DEVLINK_CMD_TRAP_GET"
    )
    DEVLINK_CMD_TRAP_GET,

    /**
     * {@code DEVLINK_CMD_TRAP_SET = 62}
     */
    @EnumMember(
        value = 62L,
        name = "DEVLINK_CMD_TRAP_SET"
    )
    DEVLINK_CMD_TRAP_SET,

    /**
     * {@code DEVLINK_CMD_TRAP_NEW = 63}
     */
    @EnumMember(
        value = 63L,
        name = "DEVLINK_CMD_TRAP_NEW"
    )
    DEVLINK_CMD_TRAP_NEW,

    /**
     * {@code DEVLINK_CMD_TRAP_DEL = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DEVLINK_CMD_TRAP_DEL"
    )
    DEVLINK_CMD_TRAP_DEL,

    /**
     * {@code DEVLINK_CMD_TRAP_GROUP_GET = 65}
     */
    @EnumMember(
        value = 65L,
        name = "DEVLINK_CMD_TRAP_GROUP_GET"
    )
    DEVLINK_CMD_TRAP_GROUP_GET,

    /**
     * {@code DEVLINK_CMD_TRAP_GROUP_SET = 66}
     */
    @EnumMember(
        value = 66L,
        name = "DEVLINK_CMD_TRAP_GROUP_SET"
    )
    DEVLINK_CMD_TRAP_GROUP_SET,

    /**
     * {@code DEVLINK_CMD_TRAP_GROUP_NEW = 67}
     */
    @EnumMember(
        value = 67L,
        name = "DEVLINK_CMD_TRAP_GROUP_NEW"
    )
    DEVLINK_CMD_TRAP_GROUP_NEW,

    /**
     * {@code DEVLINK_CMD_TRAP_GROUP_DEL = 68}
     */
    @EnumMember(
        value = 68L,
        name = "DEVLINK_CMD_TRAP_GROUP_DEL"
    )
    DEVLINK_CMD_TRAP_GROUP_DEL,

    /**
     * {@code DEVLINK_CMD_TRAP_POLICER_GET = 69}
     */
    @EnumMember(
        value = 69L,
        name = "DEVLINK_CMD_TRAP_POLICER_GET"
    )
    DEVLINK_CMD_TRAP_POLICER_GET,

    /**
     * {@code DEVLINK_CMD_TRAP_POLICER_SET = 70}
     */
    @EnumMember(
        value = 70L,
        name = "DEVLINK_CMD_TRAP_POLICER_SET"
    )
    DEVLINK_CMD_TRAP_POLICER_SET,

    /**
     * {@code DEVLINK_CMD_TRAP_POLICER_NEW = 71}
     */
    @EnumMember(
        value = 71L,
        name = "DEVLINK_CMD_TRAP_POLICER_NEW"
    )
    DEVLINK_CMD_TRAP_POLICER_NEW,

    /**
     * {@code DEVLINK_CMD_TRAP_POLICER_DEL = 72}
     */
    @EnumMember(
        value = 72L,
        name = "DEVLINK_CMD_TRAP_POLICER_DEL"
    )
    DEVLINK_CMD_TRAP_POLICER_DEL,

    /**
     * {@code DEVLINK_CMD_HEALTH_REPORTER_TEST = 73}
     */
    @EnumMember(
        value = 73L,
        name = "DEVLINK_CMD_HEALTH_REPORTER_TEST"
    )
    DEVLINK_CMD_HEALTH_REPORTER_TEST,

    /**
     * {@code DEVLINK_CMD_RATE_GET = 74}
     */
    @EnumMember(
        value = 74L,
        name = "DEVLINK_CMD_RATE_GET"
    )
    DEVLINK_CMD_RATE_GET,

    /**
     * {@code DEVLINK_CMD_RATE_SET = 75}
     */
    @EnumMember(
        value = 75L,
        name = "DEVLINK_CMD_RATE_SET"
    )
    DEVLINK_CMD_RATE_SET,

    /**
     * {@code DEVLINK_CMD_RATE_NEW = 76}
     */
    @EnumMember(
        value = 76L,
        name = "DEVLINK_CMD_RATE_NEW"
    )
    DEVLINK_CMD_RATE_NEW,

    /**
     * {@code DEVLINK_CMD_RATE_DEL = 77}
     */
    @EnumMember(
        value = 77L,
        name = "DEVLINK_CMD_RATE_DEL"
    )
    DEVLINK_CMD_RATE_DEL,

    /**
     * {@code DEVLINK_CMD_LINECARD_GET = 78}
     */
    @EnumMember(
        value = 78L,
        name = "DEVLINK_CMD_LINECARD_GET"
    )
    DEVLINK_CMD_LINECARD_GET,

    /**
     * {@code DEVLINK_CMD_LINECARD_SET = 79}
     */
    @EnumMember(
        value = 79L,
        name = "DEVLINK_CMD_LINECARD_SET"
    )
    DEVLINK_CMD_LINECARD_SET,

    /**
     * {@code DEVLINK_CMD_LINECARD_NEW = 80}
     */
    @EnumMember(
        value = 80L,
        name = "DEVLINK_CMD_LINECARD_NEW"
    )
    DEVLINK_CMD_LINECARD_NEW,

    /**
     * {@code DEVLINK_CMD_LINECARD_DEL = 81}
     */
    @EnumMember(
        value = 81L,
        name = "DEVLINK_CMD_LINECARD_DEL"
    )
    DEVLINK_CMD_LINECARD_DEL,

    /**
     * {@code DEVLINK_CMD_SELFTESTS_GET = 82}
     */
    @EnumMember(
        value = 82L,
        name = "DEVLINK_CMD_SELFTESTS_GET"
    )
    DEVLINK_CMD_SELFTESTS_GET,

    /**
     * {@code DEVLINK_CMD_SELFTESTS_RUN = 83}
     */
    @EnumMember(
        value = 83L,
        name = "DEVLINK_CMD_SELFTESTS_RUN"
    )
    DEVLINK_CMD_SELFTESTS_RUN,

    /**
     * {@code DEVLINK_CMD_NOTIFY_FILTER_SET = 84}
     */
    @EnumMember(
        value = 84L,
        name = "DEVLINK_CMD_NOTIFY_FILTER_SET"
    )
    DEVLINK_CMD_NOTIFY_FILTER_SET,

    /**
     * {@code __DEVLINK_CMD_MAX = 85}
     */
    @EnumMember(
        value = 85L,
        name = "__DEVLINK_CMD_MAX"
    )
    __DEVLINK_CMD_MAX,

    /**
     * {@code DEVLINK_CMD_MAX = 84}
     */
    @EnumMember(
        value = 84L,
        name = "DEVLINK_CMD_MAX"
    )
    DEVLINK_CMD_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_attr"
  )
  public enum devlink_attr implements Enum<devlink_attr>, TypedEnum<devlink_attr, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_ATTR_UNSPEC"
    )
    DEVLINK_ATTR_UNSPEC,

    /**
     * {@code DEVLINK_ATTR_BUS_NAME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_ATTR_BUS_NAME"
    )
    DEVLINK_ATTR_BUS_NAME,

    /**
     * {@code DEVLINK_ATTR_DEV_NAME = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_ATTR_DEV_NAME"
    )
    DEVLINK_ATTR_DEV_NAME,

    /**
     * {@code DEVLINK_ATTR_PORT_INDEX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_ATTR_PORT_INDEX"
    )
    DEVLINK_ATTR_PORT_INDEX,

    /**
     * {@code DEVLINK_ATTR_PORT_TYPE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_ATTR_PORT_TYPE"
    )
    DEVLINK_ATTR_PORT_TYPE,

    /**
     * {@code DEVLINK_ATTR_PORT_DESIRED_TYPE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_ATTR_PORT_DESIRED_TYPE"
    )
    DEVLINK_ATTR_PORT_DESIRED_TYPE,

    /**
     * {@code DEVLINK_ATTR_PORT_NETDEV_IFINDEX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_ATTR_PORT_NETDEV_IFINDEX"
    )
    DEVLINK_ATTR_PORT_NETDEV_IFINDEX,

    /**
     * {@code DEVLINK_ATTR_PORT_NETDEV_NAME = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_ATTR_PORT_NETDEV_NAME"
    )
    DEVLINK_ATTR_PORT_NETDEV_NAME,

    /**
     * {@code DEVLINK_ATTR_PORT_IBDEV_NAME = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DEVLINK_ATTR_PORT_IBDEV_NAME"
    )
    DEVLINK_ATTR_PORT_IBDEV_NAME,

    /**
     * {@code DEVLINK_ATTR_PORT_SPLIT_COUNT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DEVLINK_ATTR_PORT_SPLIT_COUNT"
    )
    DEVLINK_ATTR_PORT_SPLIT_COUNT,

    /**
     * {@code DEVLINK_ATTR_PORT_SPLIT_GROUP = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_ATTR_PORT_SPLIT_GROUP"
    )
    DEVLINK_ATTR_PORT_SPLIT_GROUP,

    /**
     * {@code DEVLINK_ATTR_SB_INDEX = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_ATTR_SB_INDEX"
    )
    DEVLINK_ATTR_SB_INDEX,

    /**
     * {@code DEVLINK_ATTR_SB_SIZE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DEVLINK_ATTR_SB_SIZE"
    )
    DEVLINK_ATTR_SB_SIZE,

    /**
     * {@code DEVLINK_ATTR_SB_INGRESS_POOL_COUNT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DEVLINK_ATTR_SB_INGRESS_POOL_COUNT"
    )
    DEVLINK_ATTR_SB_INGRESS_POOL_COUNT,

    /**
     * {@code DEVLINK_ATTR_SB_EGRESS_POOL_COUNT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DEVLINK_ATTR_SB_EGRESS_POOL_COUNT"
    )
    DEVLINK_ATTR_SB_EGRESS_POOL_COUNT,

    /**
     * {@code DEVLINK_ATTR_SB_INGRESS_TC_COUNT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DEVLINK_ATTR_SB_INGRESS_TC_COUNT"
    )
    DEVLINK_ATTR_SB_INGRESS_TC_COUNT,

    /**
     * {@code DEVLINK_ATTR_SB_EGRESS_TC_COUNT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DEVLINK_ATTR_SB_EGRESS_TC_COUNT"
    )
    DEVLINK_ATTR_SB_EGRESS_TC_COUNT,

    /**
     * {@code DEVLINK_ATTR_SB_POOL_INDEX = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DEVLINK_ATTR_SB_POOL_INDEX"
    )
    DEVLINK_ATTR_SB_POOL_INDEX,

    /**
     * {@code DEVLINK_ATTR_SB_POOL_TYPE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_ATTR_SB_POOL_TYPE"
    )
    DEVLINK_ATTR_SB_POOL_TYPE,

    /**
     * {@code DEVLINK_ATTR_SB_POOL_SIZE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "DEVLINK_ATTR_SB_POOL_SIZE"
    )
    DEVLINK_ATTR_SB_POOL_SIZE,

    /**
     * {@code DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE"
    )
    DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE,

    /**
     * {@code DEVLINK_ATTR_SB_THRESHOLD = 21}
     */
    @EnumMember(
        value = 21L,
        name = "DEVLINK_ATTR_SB_THRESHOLD"
    )
    DEVLINK_ATTR_SB_THRESHOLD,

    /**
     * {@code DEVLINK_ATTR_SB_TC_INDEX = 22}
     */
    @EnumMember(
        value = 22L,
        name = "DEVLINK_ATTR_SB_TC_INDEX"
    )
    DEVLINK_ATTR_SB_TC_INDEX,

    /**
     * {@code DEVLINK_ATTR_SB_OCC_CUR = 23}
     */
    @EnumMember(
        value = 23L,
        name = "DEVLINK_ATTR_SB_OCC_CUR"
    )
    DEVLINK_ATTR_SB_OCC_CUR,

    /**
     * {@code DEVLINK_ATTR_SB_OCC_MAX = 24}
     */
    @EnumMember(
        value = 24L,
        name = "DEVLINK_ATTR_SB_OCC_MAX"
    )
    DEVLINK_ATTR_SB_OCC_MAX,

    /**
     * {@code DEVLINK_ATTR_ESWITCH_MODE = 25}
     */
    @EnumMember(
        value = 25L,
        name = "DEVLINK_ATTR_ESWITCH_MODE"
    )
    DEVLINK_ATTR_ESWITCH_MODE,

    /**
     * {@code DEVLINK_ATTR_ESWITCH_INLINE_MODE = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DEVLINK_ATTR_ESWITCH_INLINE_MODE"
    )
    DEVLINK_ATTR_ESWITCH_INLINE_MODE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLES = 27}
     */
    @EnumMember(
        value = 27L,
        name = "DEVLINK_ATTR_DPIPE_TABLES"
    )
    DEVLINK_ATTR_DPIPE_TABLES,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "DEVLINK_ATTR_DPIPE_TABLE"
    )
    DEVLINK_ATTR_DPIPE_TABLE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_NAME = 29}
     */
    @EnumMember(
        value = 29L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_NAME"
    )
    DEVLINK_ATTR_DPIPE_TABLE_NAME,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_SIZE = 30}
     */
    @EnumMember(
        value = 30L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_SIZE"
    )
    DEVLINK_ATTR_DPIPE_TABLE_SIZE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_MATCHES = 31}
     */
    @EnumMember(
        value = 31L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_MATCHES"
    )
    DEVLINK_ATTR_DPIPE_TABLE_MATCHES,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_ACTIONS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_ACTIONS"
    )
    DEVLINK_ATTR_DPIPE_TABLE_ACTIONS,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED = 33}
     */
    @EnumMember(
        value = 33L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED"
    )
    DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRIES = 34}
     */
    @EnumMember(
        value = 34L,
        name = "DEVLINK_ATTR_DPIPE_ENTRIES"
    )
    DEVLINK_ATTR_DPIPE_ENTRIES,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRY = 35}
     */
    @EnumMember(
        value = 35L,
        name = "DEVLINK_ATTR_DPIPE_ENTRY"
    )
    DEVLINK_ATTR_DPIPE_ENTRY,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRY_INDEX = 36}
     */
    @EnumMember(
        value = 36L,
        name = "DEVLINK_ATTR_DPIPE_ENTRY_INDEX"
    )
    DEVLINK_ATTR_DPIPE_ENTRY_INDEX,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES = 37}
     */
    @EnumMember(
        value = 37L,
        name = "DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES"
    )
    DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES = 38}
     */
    @EnumMember(
        value = 38L,
        name = "DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES"
    )
    DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ENTRY_COUNTER = 39}
     */
    @EnumMember(
        value = 39L,
        name = "DEVLINK_ATTR_DPIPE_ENTRY_COUNTER"
    )
    DEVLINK_ATTR_DPIPE_ENTRY_COUNTER,

    /**
     * {@code DEVLINK_ATTR_DPIPE_MATCH = 40}
     */
    @EnumMember(
        value = 40L,
        name = "DEVLINK_ATTR_DPIPE_MATCH"
    )
    DEVLINK_ATTR_DPIPE_MATCH,

    /**
     * {@code DEVLINK_ATTR_DPIPE_MATCH_VALUE = 41}
     */
    @EnumMember(
        value = 41L,
        name = "DEVLINK_ATTR_DPIPE_MATCH_VALUE"
    )
    DEVLINK_ATTR_DPIPE_MATCH_VALUE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_MATCH_TYPE = 42}
     */
    @EnumMember(
        value = 42L,
        name = "DEVLINK_ATTR_DPIPE_MATCH_TYPE"
    )
    DEVLINK_ATTR_DPIPE_MATCH_TYPE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ACTION = 43}
     */
    @EnumMember(
        value = 43L,
        name = "DEVLINK_ATTR_DPIPE_ACTION"
    )
    DEVLINK_ATTR_DPIPE_ACTION,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ACTION_VALUE = 44}
     */
    @EnumMember(
        value = 44L,
        name = "DEVLINK_ATTR_DPIPE_ACTION_VALUE"
    )
    DEVLINK_ATTR_DPIPE_ACTION_VALUE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_ACTION_TYPE = 45}
     */
    @EnumMember(
        value = 45L,
        name = "DEVLINK_ATTR_DPIPE_ACTION_TYPE"
    )
    DEVLINK_ATTR_DPIPE_ACTION_TYPE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_VALUE = 46}
     */
    @EnumMember(
        value = 46L,
        name = "DEVLINK_ATTR_DPIPE_VALUE"
    )
    DEVLINK_ATTR_DPIPE_VALUE,

    /**
     * {@code DEVLINK_ATTR_DPIPE_VALUE_MASK = 47}
     */
    @EnumMember(
        value = 47L,
        name = "DEVLINK_ATTR_DPIPE_VALUE_MASK"
    )
    DEVLINK_ATTR_DPIPE_VALUE_MASK,

    /**
     * {@code DEVLINK_ATTR_DPIPE_VALUE_MAPPING = 48}
     */
    @EnumMember(
        value = 48L,
        name = "DEVLINK_ATTR_DPIPE_VALUE_MAPPING"
    )
    DEVLINK_ATTR_DPIPE_VALUE_MAPPING,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADERS = 49}
     */
    @EnumMember(
        value = 49L,
        name = "DEVLINK_ATTR_DPIPE_HEADERS"
    )
    DEVLINK_ATTR_DPIPE_HEADERS,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER = 50}
     */
    @EnumMember(
        value = 50L,
        name = "DEVLINK_ATTR_DPIPE_HEADER"
    )
    DEVLINK_ATTR_DPIPE_HEADER,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER_NAME = 51}
     */
    @EnumMember(
        value = 51L,
        name = "DEVLINK_ATTR_DPIPE_HEADER_NAME"
    )
    DEVLINK_ATTR_DPIPE_HEADER_NAME,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER_ID = 52}
     */
    @EnumMember(
        value = 52L,
        name = "DEVLINK_ATTR_DPIPE_HEADER_ID"
    )
    DEVLINK_ATTR_DPIPE_HEADER_ID,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER_FIELDS = 53}
     */
    @EnumMember(
        value = 53L,
        name = "DEVLINK_ATTR_DPIPE_HEADER_FIELDS"
    )
    DEVLINK_ATTR_DPIPE_HEADER_FIELDS,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER_GLOBAL = 54}
     */
    @EnumMember(
        value = 54L,
        name = "DEVLINK_ATTR_DPIPE_HEADER_GLOBAL"
    )
    DEVLINK_ATTR_DPIPE_HEADER_GLOBAL,

    /**
     * {@code DEVLINK_ATTR_DPIPE_HEADER_INDEX = 55}
     */
    @EnumMember(
        value = 55L,
        name = "DEVLINK_ATTR_DPIPE_HEADER_INDEX"
    )
    DEVLINK_ATTR_DPIPE_HEADER_INDEX,

    /**
     * {@code DEVLINK_ATTR_DPIPE_FIELD = 56}
     */
    @EnumMember(
        value = 56L,
        name = "DEVLINK_ATTR_DPIPE_FIELD"
    )
    DEVLINK_ATTR_DPIPE_FIELD,

    /**
     * {@code DEVLINK_ATTR_DPIPE_FIELD_NAME = 57}
     */
    @EnumMember(
        value = 57L,
        name = "DEVLINK_ATTR_DPIPE_FIELD_NAME"
    )
    DEVLINK_ATTR_DPIPE_FIELD_NAME,

    /**
     * {@code DEVLINK_ATTR_DPIPE_FIELD_ID = 58}
     */
    @EnumMember(
        value = 58L,
        name = "DEVLINK_ATTR_DPIPE_FIELD_ID"
    )
    DEVLINK_ATTR_DPIPE_FIELD_ID,

    /**
     * {@code DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH = 59}
     */
    @EnumMember(
        value = 59L,
        name = "DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH"
    )
    DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH,

    /**
     * {@code DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE = 60}
     */
    @EnumMember(
        value = 60L,
        name = "DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE"
    )
    DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE,

    /**
     * {@code DEVLINK_ATTR_PAD = 61}
     */
    @EnumMember(
        value = 61L,
        name = "DEVLINK_ATTR_PAD"
    )
    DEVLINK_ATTR_PAD,

    /**
     * {@code DEVLINK_ATTR_ESWITCH_ENCAP_MODE = 62}
     */
    @EnumMember(
        value = 62L,
        name = "DEVLINK_ATTR_ESWITCH_ENCAP_MODE"
    )
    DEVLINK_ATTR_ESWITCH_ENCAP_MODE,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_LIST = 63}
     */
    @EnumMember(
        value = 63L,
        name = "DEVLINK_ATTR_RESOURCE_LIST"
    )
    DEVLINK_ATTR_RESOURCE_LIST,

    /**
     * {@code DEVLINK_ATTR_RESOURCE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DEVLINK_ATTR_RESOURCE"
    )
    DEVLINK_ATTR_RESOURCE,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_NAME = 65}
     */
    @EnumMember(
        value = 65L,
        name = "DEVLINK_ATTR_RESOURCE_NAME"
    )
    DEVLINK_ATTR_RESOURCE_NAME,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_ID = 66}
     */
    @EnumMember(
        value = 66L,
        name = "DEVLINK_ATTR_RESOURCE_ID"
    )
    DEVLINK_ATTR_RESOURCE_ID,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE = 67}
     */
    @EnumMember(
        value = 67L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE"
    )
    DEVLINK_ATTR_RESOURCE_SIZE,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE_NEW = 68}
     */
    @EnumMember(
        value = 68L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE_NEW"
    )
    DEVLINK_ATTR_RESOURCE_SIZE_NEW,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE_VALID = 69}
     */
    @EnumMember(
        value = 69L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE_VALID"
    )
    DEVLINK_ATTR_RESOURCE_SIZE_VALID,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE_MIN = 70}
     */
    @EnumMember(
        value = 70L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE_MIN"
    )
    DEVLINK_ATTR_RESOURCE_SIZE_MIN,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE_MAX = 71}
     */
    @EnumMember(
        value = 71L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE_MAX"
    )
    DEVLINK_ATTR_RESOURCE_SIZE_MAX,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_SIZE_GRAN = 72}
     */
    @EnumMember(
        value = 72L,
        name = "DEVLINK_ATTR_RESOURCE_SIZE_GRAN"
    )
    DEVLINK_ATTR_RESOURCE_SIZE_GRAN,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_UNIT = 73}
     */
    @EnumMember(
        value = 73L,
        name = "DEVLINK_ATTR_RESOURCE_UNIT"
    )
    DEVLINK_ATTR_RESOURCE_UNIT,

    /**
     * {@code DEVLINK_ATTR_RESOURCE_OCC = 74}
     */
    @EnumMember(
        value = 74L,
        name = "DEVLINK_ATTR_RESOURCE_OCC"
    )
    DEVLINK_ATTR_RESOURCE_OCC,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID = 75}
     */
    @EnumMember(
        value = 75L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID"
    )
    DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID,

    /**
     * {@code DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS = 76}
     */
    @EnumMember(
        value = 76L,
        name = "DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS"
    )
    DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS,

    /**
     * {@code DEVLINK_ATTR_PORT_FLAVOUR = 77}
     */
    @EnumMember(
        value = 77L,
        name = "DEVLINK_ATTR_PORT_FLAVOUR"
    )
    DEVLINK_ATTR_PORT_FLAVOUR,

    /**
     * {@code DEVLINK_ATTR_PORT_NUMBER = 78}
     */
    @EnumMember(
        value = 78L,
        name = "DEVLINK_ATTR_PORT_NUMBER"
    )
    DEVLINK_ATTR_PORT_NUMBER,

    /**
     * {@code DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER = 79}
     */
    @EnumMember(
        value = 79L,
        name = "DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER"
    )
    DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER,

    /**
     * {@code DEVLINK_ATTR_PARAM = 80}
     */
    @EnumMember(
        value = 80L,
        name = "DEVLINK_ATTR_PARAM"
    )
    DEVLINK_ATTR_PARAM,

    /**
     * {@code DEVLINK_ATTR_PARAM_NAME = 81}
     */
    @EnumMember(
        value = 81L,
        name = "DEVLINK_ATTR_PARAM_NAME"
    )
    DEVLINK_ATTR_PARAM_NAME,

    /**
     * {@code DEVLINK_ATTR_PARAM_GENERIC = 82}
     */
    @EnumMember(
        value = 82L,
        name = "DEVLINK_ATTR_PARAM_GENERIC"
    )
    DEVLINK_ATTR_PARAM_GENERIC,

    /**
     * {@code DEVLINK_ATTR_PARAM_TYPE = 83}
     */
    @EnumMember(
        value = 83L,
        name = "DEVLINK_ATTR_PARAM_TYPE"
    )
    DEVLINK_ATTR_PARAM_TYPE,

    /**
     * {@code DEVLINK_ATTR_PARAM_VALUES_LIST = 84}
     */
    @EnumMember(
        value = 84L,
        name = "DEVLINK_ATTR_PARAM_VALUES_LIST"
    )
    DEVLINK_ATTR_PARAM_VALUES_LIST,

    /**
     * {@code DEVLINK_ATTR_PARAM_VALUE = 85}
     */
    @EnumMember(
        value = 85L,
        name = "DEVLINK_ATTR_PARAM_VALUE"
    )
    DEVLINK_ATTR_PARAM_VALUE,

    /**
     * {@code DEVLINK_ATTR_PARAM_VALUE_DATA = 86}
     */
    @EnumMember(
        value = 86L,
        name = "DEVLINK_ATTR_PARAM_VALUE_DATA"
    )
    DEVLINK_ATTR_PARAM_VALUE_DATA,

    /**
     * {@code DEVLINK_ATTR_PARAM_VALUE_CMODE = 87}
     */
    @EnumMember(
        value = 87L,
        name = "DEVLINK_ATTR_PARAM_VALUE_CMODE"
    )
    DEVLINK_ATTR_PARAM_VALUE_CMODE,

    /**
     * {@code DEVLINK_ATTR_REGION_NAME = 88}
     */
    @EnumMember(
        value = 88L,
        name = "DEVLINK_ATTR_REGION_NAME"
    )
    DEVLINK_ATTR_REGION_NAME,

    /**
     * {@code DEVLINK_ATTR_REGION_SIZE = 89}
     */
    @EnumMember(
        value = 89L,
        name = "DEVLINK_ATTR_REGION_SIZE"
    )
    DEVLINK_ATTR_REGION_SIZE,

    /**
     * {@code DEVLINK_ATTR_REGION_SNAPSHOTS = 90}
     */
    @EnumMember(
        value = 90L,
        name = "DEVLINK_ATTR_REGION_SNAPSHOTS"
    )
    DEVLINK_ATTR_REGION_SNAPSHOTS,

    /**
     * {@code DEVLINK_ATTR_REGION_SNAPSHOT = 91}
     */
    @EnumMember(
        value = 91L,
        name = "DEVLINK_ATTR_REGION_SNAPSHOT"
    )
    DEVLINK_ATTR_REGION_SNAPSHOT,

    /**
     * {@code DEVLINK_ATTR_REGION_SNAPSHOT_ID = 92}
     */
    @EnumMember(
        value = 92L,
        name = "DEVLINK_ATTR_REGION_SNAPSHOT_ID"
    )
    DEVLINK_ATTR_REGION_SNAPSHOT_ID,

    /**
     * {@code DEVLINK_ATTR_REGION_CHUNKS = 93}
     */
    @EnumMember(
        value = 93L,
        name = "DEVLINK_ATTR_REGION_CHUNKS"
    )
    DEVLINK_ATTR_REGION_CHUNKS,

    /**
     * {@code DEVLINK_ATTR_REGION_CHUNK = 94}
     */
    @EnumMember(
        value = 94L,
        name = "DEVLINK_ATTR_REGION_CHUNK"
    )
    DEVLINK_ATTR_REGION_CHUNK,

    /**
     * {@code DEVLINK_ATTR_REGION_CHUNK_DATA = 95}
     */
    @EnumMember(
        value = 95L,
        name = "DEVLINK_ATTR_REGION_CHUNK_DATA"
    )
    DEVLINK_ATTR_REGION_CHUNK_DATA,

    /**
     * {@code DEVLINK_ATTR_REGION_CHUNK_ADDR = 96}
     */
    @EnumMember(
        value = 96L,
        name = "DEVLINK_ATTR_REGION_CHUNK_ADDR"
    )
    DEVLINK_ATTR_REGION_CHUNK_ADDR,

    /**
     * {@code DEVLINK_ATTR_REGION_CHUNK_LEN = 97}
     */
    @EnumMember(
        value = 97L,
        name = "DEVLINK_ATTR_REGION_CHUNK_LEN"
    )
    DEVLINK_ATTR_REGION_CHUNK_LEN,

    /**
     * {@code DEVLINK_ATTR_INFO_DRIVER_NAME = 98}
     */
    @EnumMember(
        value = 98L,
        name = "DEVLINK_ATTR_INFO_DRIVER_NAME"
    )
    DEVLINK_ATTR_INFO_DRIVER_NAME,

    /**
     * {@code DEVLINK_ATTR_INFO_SERIAL_NUMBER = 99}
     */
    @EnumMember(
        value = 99L,
        name = "DEVLINK_ATTR_INFO_SERIAL_NUMBER"
    )
    DEVLINK_ATTR_INFO_SERIAL_NUMBER,

    /**
     * {@code DEVLINK_ATTR_INFO_VERSION_FIXED = 100}
     */
    @EnumMember(
        value = 100L,
        name = "DEVLINK_ATTR_INFO_VERSION_FIXED"
    )
    DEVLINK_ATTR_INFO_VERSION_FIXED,

    /**
     * {@code DEVLINK_ATTR_INFO_VERSION_RUNNING = 101}
     */
    @EnumMember(
        value = 101L,
        name = "DEVLINK_ATTR_INFO_VERSION_RUNNING"
    )
    DEVLINK_ATTR_INFO_VERSION_RUNNING,

    /**
     * {@code DEVLINK_ATTR_INFO_VERSION_STORED = 102}
     */
    @EnumMember(
        value = 102L,
        name = "DEVLINK_ATTR_INFO_VERSION_STORED"
    )
    DEVLINK_ATTR_INFO_VERSION_STORED,

    /**
     * {@code DEVLINK_ATTR_INFO_VERSION_NAME = 103}
     */
    @EnumMember(
        value = 103L,
        name = "DEVLINK_ATTR_INFO_VERSION_NAME"
    )
    DEVLINK_ATTR_INFO_VERSION_NAME,

    /**
     * {@code DEVLINK_ATTR_INFO_VERSION_VALUE = 104}
     */
    @EnumMember(
        value = 104L,
        name = "DEVLINK_ATTR_INFO_VERSION_VALUE"
    )
    DEVLINK_ATTR_INFO_VERSION_VALUE,

    /**
     * {@code DEVLINK_ATTR_SB_POOL_CELL_SIZE = 105}
     */
    @EnumMember(
        value = 105L,
        name = "DEVLINK_ATTR_SB_POOL_CELL_SIZE"
    )
    DEVLINK_ATTR_SB_POOL_CELL_SIZE,

    /**
     * {@code DEVLINK_ATTR_FMSG = 106}
     */
    @EnumMember(
        value = 106L,
        name = "DEVLINK_ATTR_FMSG"
    )
    DEVLINK_ATTR_FMSG,

    /**
     * {@code DEVLINK_ATTR_FMSG_OBJ_NEST_START = 107}
     */
    @EnumMember(
        value = 107L,
        name = "DEVLINK_ATTR_FMSG_OBJ_NEST_START"
    )
    DEVLINK_ATTR_FMSG_OBJ_NEST_START,

    /**
     * {@code DEVLINK_ATTR_FMSG_PAIR_NEST_START = 108}
     */
    @EnumMember(
        value = 108L,
        name = "DEVLINK_ATTR_FMSG_PAIR_NEST_START"
    )
    DEVLINK_ATTR_FMSG_PAIR_NEST_START,

    /**
     * {@code DEVLINK_ATTR_FMSG_ARR_NEST_START = 109}
     */
    @EnumMember(
        value = 109L,
        name = "DEVLINK_ATTR_FMSG_ARR_NEST_START"
    )
    DEVLINK_ATTR_FMSG_ARR_NEST_START,

    /**
     * {@code DEVLINK_ATTR_FMSG_NEST_END = 110}
     */
    @EnumMember(
        value = 110L,
        name = "DEVLINK_ATTR_FMSG_NEST_END"
    )
    DEVLINK_ATTR_FMSG_NEST_END,

    /**
     * {@code DEVLINK_ATTR_FMSG_OBJ_NAME = 111}
     */
    @EnumMember(
        value = 111L,
        name = "DEVLINK_ATTR_FMSG_OBJ_NAME"
    )
    DEVLINK_ATTR_FMSG_OBJ_NAME,

    /**
     * {@code DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE = 112}
     */
    @EnumMember(
        value = 112L,
        name = "DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE"
    )
    DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE,

    /**
     * {@code DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA = 113}
     */
    @EnumMember(
        value = 113L,
        name = "DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA"
    )
    DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER = 114}
     */
    @EnumMember(
        value = 114L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER"
    )
    DEVLINK_ATTR_HEALTH_REPORTER,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_NAME = 115}
     */
    @EnumMember(
        value = 115L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_NAME"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_NAME,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_STATE = 116}
     */
    @EnumMember(
        value = 116L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_STATE"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_STATE,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT = 117}
     */
    @EnumMember(
        value = 117L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT = 118}
     */
    @EnumMember(
        value = 118L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS = 119}
     */
    @EnumMember(
        value = 119L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD = 120}
     */
    @EnumMember(
        value = 120L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER = 121}
     */
    @EnumMember(
        value = 121L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME = 122}
     */
    @EnumMember(
        value = 122L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME"
    )
    DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_COMPONENT = 123}
     */
    @EnumMember(
        value = 123L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_COMPONENT"
    )
    DEVLINK_ATTR_FLASH_UPDATE_COMPONENT,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG = 124}
     */
    @EnumMember(
        value = 124L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG"
    )
    DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE = 125}
     */
    @EnumMember(
        value = 125L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE"
    )
    DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL = 126}
     */
    @EnumMember(
        value = 126L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL"
    )
    DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL,

    /**
     * {@code DEVLINK_ATTR_PORT_PCI_PF_NUMBER = 127}
     */
    @EnumMember(
        value = 127L,
        name = "DEVLINK_ATTR_PORT_PCI_PF_NUMBER"
    )
    DEVLINK_ATTR_PORT_PCI_PF_NUMBER,

    /**
     * {@code DEVLINK_ATTR_PORT_PCI_VF_NUMBER = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DEVLINK_ATTR_PORT_PCI_VF_NUMBER"
    )
    DEVLINK_ATTR_PORT_PCI_VF_NUMBER,

    /**
     * {@code DEVLINK_ATTR_STATS = 129}
     */
    @EnumMember(
        value = 129L,
        name = "DEVLINK_ATTR_STATS"
    )
    DEVLINK_ATTR_STATS,

    /**
     * {@code DEVLINK_ATTR_TRAP_NAME = 130}
     */
    @EnumMember(
        value = 130L,
        name = "DEVLINK_ATTR_TRAP_NAME"
    )
    DEVLINK_ATTR_TRAP_NAME,

    /**
     * {@code DEVLINK_ATTR_TRAP_ACTION = 131}
     */
    @EnumMember(
        value = 131L,
        name = "DEVLINK_ATTR_TRAP_ACTION"
    )
    DEVLINK_ATTR_TRAP_ACTION,

    /**
     * {@code DEVLINK_ATTR_TRAP_TYPE = 132}
     */
    @EnumMember(
        value = 132L,
        name = "DEVLINK_ATTR_TRAP_TYPE"
    )
    DEVLINK_ATTR_TRAP_TYPE,

    /**
     * {@code DEVLINK_ATTR_TRAP_GENERIC = 133}
     */
    @EnumMember(
        value = 133L,
        name = "DEVLINK_ATTR_TRAP_GENERIC"
    )
    DEVLINK_ATTR_TRAP_GENERIC,

    /**
     * {@code DEVLINK_ATTR_TRAP_METADATA = 134}
     */
    @EnumMember(
        value = 134L,
        name = "DEVLINK_ATTR_TRAP_METADATA"
    )
    DEVLINK_ATTR_TRAP_METADATA,

    /**
     * {@code DEVLINK_ATTR_TRAP_GROUP_NAME = 135}
     */
    @EnumMember(
        value = 135L,
        name = "DEVLINK_ATTR_TRAP_GROUP_NAME"
    )
    DEVLINK_ATTR_TRAP_GROUP_NAME,

    /**
     * {@code DEVLINK_ATTR_RELOAD_FAILED = 136}
     */
    @EnumMember(
        value = 136L,
        name = "DEVLINK_ATTR_RELOAD_FAILED"
    )
    DEVLINK_ATTR_RELOAD_FAILED,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS = 137}
     */
    @EnumMember(
        value = 137L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS,

    /**
     * {@code DEVLINK_ATTR_NETNS_FD = 138}
     */
    @EnumMember(
        value = 138L,
        name = "DEVLINK_ATTR_NETNS_FD"
    )
    DEVLINK_ATTR_NETNS_FD,

    /**
     * {@code DEVLINK_ATTR_NETNS_PID = 139}
     */
    @EnumMember(
        value = 139L,
        name = "DEVLINK_ATTR_NETNS_PID"
    )
    DEVLINK_ATTR_NETNS_PID,

    /**
     * {@code DEVLINK_ATTR_NETNS_ID = 140}
     */
    @EnumMember(
        value = 140L,
        name = "DEVLINK_ATTR_NETNS_ID"
    )
    DEVLINK_ATTR_NETNS_ID,

    /**
     * {@code DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP = 141}
     */
    @EnumMember(
        value = 141L,
        name = "DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP"
    )
    DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP,

    /**
     * {@code DEVLINK_ATTR_TRAP_POLICER_ID = 142}
     */
    @EnumMember(
        value = 142L,
        name = "DEVLINK_ATTR_TRAP_POLICER_ID"
    )
    DEVLINK_ATTR_TRAP_POLICER_ID,

    /**
     * {@code DEVLINK_ATTR_TRAP_POLICER_RATE = 143}
     */
    @EnumMember(
        value = 143L,
        name = "DEVLINK_ATTR_TRAP_POLICER_RATE"
    )
    DEVLINK_ATTR_TRAP_POLICER_RATE,

    /**
     * {@code DEVLINK_ATTR_TRAP_POLICER_BURST = 144}
     */
    @EnumMember(
        value = 144L,
        name = "DEVLINK_ATTR_TRAP_POLICER_BURST"
    )
    DEVLINK_ATTR_TRAP_POLICER_BURST,

    /**
     * {@code DEVLINK_ATTR_PORT_FUNCTION = 145}
     */
    @EnumMember(
        value = 145L,
        name = "DEVLINK_ATTR_PORT_FUNCTION"
    )
    DEVLINK_ATTR_PORT_FUNCTION,

    /**
     * {@code DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER = 146}
     */
    @EnumMember(
        value = 146L,
        name = "DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER"
    )
    DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER,

    /**
     * {@code DEVLINK_ATTR_PORT_LANES = 147}
     */
    @EnumMember(
        value = 147L,
        name = "DEVLINK_ATTR_PORT_LANES"
    )
    DEVLINK_ATTR_PORT_LANES,

    /**
     * {@code DEVLINK_ATTR_PORT_SPLITTABLE = 148}
     */
    @EnumMember(
        value = 148L,
        name = "DEVLINK_ATTR_PORT_SPLITTABLE"
    )
    DEVLINK_ATTR_PORT_SPLITTABLE,

    /**
     * {@code DEVLINK_ATTR_PORT_EXTERNAL = 149}
     */
    @EnumMember(
        value = 149L,
        name = "DEVLINK_ATTR_PORT_EXTERNAL"
    )
    DEVLINK_ATTR_PORT_EXTERNAL,

    /**
     * {@code DEVLINK_ATTR_PORT_CONTROLLER_NUMBER = 150}
     */
    @EnumMember(
        value = 150L,
        name = "DEVLINK_ATTR_PORT_CONTROLLER_NUMBER"
    )
    DEVLINK_ATTR_PORT_CONTROLLER_NUMBER,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT = 151}
     */
    @EnumMember(
        value = 151L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT"
    )
    DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT,

    /**
     * {@code DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK = 152}
     */
    @EnumMember(
        value = 152L,
        name = "DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK"
    )
    DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK,

    /**
     * {@code DEVLINK_ATTR_RELOAD_ACTION = 153}
     */
    @EnumMember(
        value = 153L,
        name = "DEVLINK_ATTR_RELOAD_ACTION"
    )
    DEVLINK_ATTR_RELOAD_ACTION,

    /**
     * {@code DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED = 154}
     */
    @EnumMember(
        value = 154L,
        name = "DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED"
    )
    DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED,

    /**
     * {@code DEVLINK_ATTR_RELOAD_LIMITS = 155}
     */
    @EnumMember(
        value = 155L,
        name = "DEVLINK_ATTR_RELOAD_LIMITS"
    )
    DEVLINK_ATTR_RELOAD_LIMITS,

    /**
     * {@code DEVLINK_ATTR_DEV_STATS = 156}
     */
    @EnumMember(
        value = 156L,
        name = "DEVLINK_ATTR_DEV_STATS"
    )
    DEVLINK_ATTR_DEV_STATS,

    /**
     * {@code DEVLINK_ATTR_RELOAD_STATS = 157}
     */
    @EnumMember(
        value = 157L,
        name = "DEVLINK_ATTR_RELOAD_STATS"
    )
    DEVLINK_ATTR_RELOAD_STATS,

    /**
     * {@code DEVLINK_ATTR_RELOAD_STATS_ENTRY = 158}
     */
    @EnumMember(
        value = 158L,
        name = "DEVLINK_ATTR_RELOAD_STATS_ENTRY"
    )
    DEVLINK_ATTR_RELOAD_STATS_ENTRY,

    /**
     * {@code DEVLINK_ATTR_RELOAD_STATS_LIMIT = 159}
     */
    @EnumMember(
        value = 159L,
        name = "DEVLINK_ATTR_RELOAD_STATS_LIMIT"
    )
    DEVLINK_ATTR_RELOAD_STATS_LIMIT,

    /**
     * {@code DEVLINK_ATTR_RELOAD_STATS_VALUE = 160}
     */
    @EnumMember(
        value = 160L,
        name = "DEVLINK_ATTR_RELOAD_STATS_VALUE"
    )
    DEVLINK_ATTR_RELOAD_STATS_VALUE,

    /**
     * {@code DEVLINK_ATTR_REMOTE_RELOAD_STATS = 161}
     */
    @EnumMember(
        value = 161L,
        name = "DEVLINK_ATTR_REMOTE_RELOAD_STATS"
    )
    DEVLINK_ATTR_REMOTE_RELOAD_STATS,

    /**
     * {@code DEVLINK_ATTR_RELOAD_ACTION_INFO = 162}
     */
    @EnumMember(
        value = 162L,
        name = "DEVLINK_ATTR_RELOAD_ACTION_INFO"
    )
    DEVLINK_ATTR_RELOAD_ACTION_INFO,

    /**
     * {@code DEVLINK_ATTR_RELOAD_ACTION_STATS = 163}
     */
    @EnumMember(
        value = 163L,
        name = "DEVLINK_ATTR_RELOAD_ACTION_STATS"
    )
    DEVLINK_ATTR_RELOAD_ACTION_STATS,

    /**
     * {@code DEVLINK_ATTR_PORT_PCI_SF_NUMBER = 164}
     */
    @EnumMember(
        value = 164L,
        name = "DEVLINK_ATTR_PORT_PCI_SF_NUMBER"
    )
    DEVLINK_ATTR_PORT_PCI_SF_NUMBER,

    /**
     * {@code DEVLINK_ATTR_RATE_TYPE = 165}
     */
    @EnumMember(
        value = 165L,
        name = "DEVLINK_ATTR_RATE_TYPE"
    )
    DEVLINK_ATTR_RATE_TYPE,

    /**
     * {@code DEVLINK_ATTR_RATE_TX_SHARE = 166}
     */
    @EnumMember(
        value = 166L,
        name = "DEVLINK_ATTR_RATE_TX_SHARE"
    )
    DEVLINK_ATTR_RATE_TX_SHARE,

    /**
     * {@code DEVLINK_ATTR_RATE_TX_MAX = 167}
     */
    @EnumMember(
        value = 167L,
        name = "DEVLINK_ATTR_RATE_TX_MAX"
    )
    DEVLINK_ATTR_RATE_TX_MAX,

    /**
     * {@code DEVLINK_ATTR_RATE_NODE_NAME = 168}
     */
    @EnumMember(
        value = 168L,
        name = "DEVLINK_ATTR_RATE_NODE_NAME"
    )
    DEVLINK_ATTR_RATE_NODE_NAME,

    /**
     * {@code DEVLINK_ATTR_RATE_PARENT_NODE_NAME = 169}
     */
    @EnumMember(
        value = 169L,
        name = "DEVLINK_ATTR_RATE_PARENT_NODE_NAME"
    )
    DEVLINK_ATTR_RATE_PARENT_NODE_NAME,

    /**
     * {@code DEVLINK_ATTR_REGION_MAX_SNAPSHOTS = 170}
     */
    @EnumMember(
        value = 170L,
        name = "DEVLINK_ATTR_REGION_MAX_SNAPSHOTS"
    )
    DEVLINK_ATTR_REGION_MAX_SNAPSHOTS,

    /**
     * {@code DEVLINK_ATTR_LINECARD_INDEX = 171}
     */
    @EnumMember(
        value = 171L,
        name = "DEVLINK_ATTR_LINECARD_INDEX"
    )
    DEVLINK_ATTR_LINECARD_INDEX,

    /**
     * {@code DEVLINK_ATTR_LINECARD_STATE = 172}
     */
    @EnumMember(
        value = 172L,
        name = "DEVLINK_ATTR_LINECARD_STATE"
    )
    DEVLINK_ATTR_LINECARD_STATE,

    /**
     * {@code DEVLINK_ATTR_LINECARD_TYPE = 173}
     */
    @EnumMember(
        value = 173L,
        name = "DEVLINK_ATTR_LINECARD_TYPE"
    )
    DEVLINK_ATTR_LINECARD_TYPE,

    /**
     * {@code DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES = 174}
     */
    @EnumMember(
        value = 174L,
        name = "DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES"
    )
    DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES,

    /**
     * {@code DEVLINK_ATTR_NESTED_DEVLINK = 175}
     */
    @EnumMember(
        value = 175L,
        name = "DEVLINK_ATTR_NESTED_DEVLINK"
    )
    DEVLINK_ATTR_NESTED_DEVLINK,

    /**
     * {@code DEVLINK_ATTR_SELFTESTS = 176}
     */
    @EnumMember(
        value = 176L,
        name = "DEVLINK_ATTR_SELFTESTS"
    )
    DEVLINK_ATTR_SELFTESTS,

    /**
     * {@code DEVLINK_ATTR_RATE_TX_PRIORITY = 177}
     */
    @EnumMember(
        value = 177L,
        name = "DEVLINK_ATTR_RATE_TX_PRIORITY"
    )
    DEVLINK_ATTR_RATE_TX_PRIORITY,

    /**
     * {@code DEVLINK_ATTR_RATE_TX_WEIGHT = 178}
     */
    @EnumMember(
        value = 178L,
        name = "DEVLINK_ATTR_RATE_TX_WEIGHT"
    )
    DEVLINK_ATTR_RATE_TX_WEIGHT,

    /**
     * {@code DEVLINK_ATTR_REGION_DIRECT = 179}
     */
    @EnumMember(
        value = 179L,
        name = "DEVLINK_ATTR_REGION_DIRECT"
    )
    DEVLINK_ATTR_REGION_DIRECT,

    /**
     * {@code DEVLINK_ATTR_RATE_TC_BWS = 180}
     */
    @EnumMember(
        value = 180L,
        name = "DEVLINK_ATTR_RATE_TC_BWS"
    )
    DEVLINK_ATTR_RATE_TC_BWS,

    /**
     * {@code __DEVLINK_ATTR_MAX = 181}
     */
    @EnumMember(
        value = 181L,
        name = "__DEVLINK_ATTR_MAX"
    )
    __DEVLINK_ATTR_MAX,

    /**
     * {@code DEVLINK_ATTR_MAX = 180}
     */
    @EnumMember(
        value = 180L,
        name = "DEVLINK_ATTR_MAX"
    )
    DEVLINK_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_multicast_groups"
  )
  public enum devlink_multicast_groups implements Enum<devlink_multicast_groups>, TypedEnum<devlink_multicast_groups, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_MCGRP_CONFIG = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_MCGRP_CONFIG"
    )
    DEVLINK_MCGRP_CONFIG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_nl_dump_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_nl_dump_state extends Struct {
    public @Unsigned long instance;

    public int idx;

    @InlineUnion(63823)
    public anon_member_of_anon_member_of_devlink_nl_dump_state anon2$0;

    @InlineUnion(63823)
    public anon_member_of_anon_member_of_devlink_nl_dump_state anon2$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_obj_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_obj_desc extends Struct {
    public callback_head rcu;

    public String bus_name;

    public String dev_name;

    public @Unsigned int port_index;

    public boolean port_index_valid;

    public long @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_nl_sock_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_nl_sock_priv extends Struct {
    public Ptr<devlink_obj_desc> flt;

    public @OriginalName("spinlock_t") spinlock flt_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_var_attr_type"
  )
  public enum devlink_var_attr_type implements Enum<devlink_var_attr_type>, TypedEnum<devlink_var_attr_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_U8 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_VAR_ATTR_TYPE_U8"
    )
    DEVLINK_VAR_ATTR_TYPE_U8,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_U16 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_VAR_ATTR_TYPE_U16"
    )
    DEVLINK_VAR_ATTR_TYPE_U16,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_U32 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_VAR_ATTR_TYPE_U32"
    )
    DEVLINK_VAR_ATTR_TYPE_U32,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_U64 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_VAR_ATTR_TYPE_U64"
    )
    DEVLINK_VAR_ATTR_TYPE_U64,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_STRING = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_VAR_ATTR_TYPE_STRING"
    )
    DEVLINK_VAR_ATTR_TYPE_STRING,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_FLAG = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_VAR_ATTR_TYPE_FLAG"
    )
    DEVLINK_VAR_ATTR_TYPE_FLAG,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_NUL_STRING = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_VAR_ATTR_TYPE_NUL_STRING"
    )
    DEVLINK_VAR_ATTR_TYPE_NUL_STRING,

    /**
     * {@code DEVLINK_VAR_ATTR_TYPE_BINARY = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_VAR_ATTR_TYPE_BINARY"
    )
    DEVLINK_VAR_ATTR_TYPE_BINARY,

    /**
     * {@code __DEVLINK_VAR_ATTR_TYPE_CUSTOM_BASE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "__DEVLINK_VAR_ATTR_TYPE_CUSTOM_BASE"
    )
    __DEVLINK_VAR_ATTR_TYPE_CUSTOM_BASE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_attr_selftest_result"
  )
  public enum devlink_attr_selftest_result implements Enum<devlink_attr_selftest_result>, TypedEnum<devlink_attr_selftest_result, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_ATTR_SELFTEST_RESULT_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_ATTR_SELFTEST_RESULT_UNSPEC"
    )
    DEVLINK_ATTR_SELFTEST_RESULT_UNSPEC,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_RESULT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_ATTR_SELFTEST_RESULT"
    )
    DEVLINK_ATTR_SELFTEST_RESULT,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_RESULT_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_ATTR_SELFTEST_RESULT_ID"
    )
    DEVLINK_ATTR_SELFTEST_RESULT_ID,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_RESULT_STATUS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_ATTR_SELFTEST_RESULT_STATUS"
    )
    DEVLINK_ATTR_SELFTEST_RESULT_STATUS,

    /**
     * {@code __DEVLINK_ATTR_SELFTEST_RESULT_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__DEVLINK_ATTR_SELFTEST_RESULT_MAX"
    )
    __DEVLINK_ATTR_SELFTEST_RESULT_MAX,

    /**
     * {@code DEVLINK_ATTR_SELFTEST_RESULT_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_ATTR_SELFTEST_RESULT_MAX"
    )
    DEVLINK_ATTR_SELFTEST_RESULT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_flash_notify"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_flash_notify extends Struct {
    public String status_msg;

    public String component;

    public @Unsigned long done;

    public @Unsigned long total;

    public @Unsigned long timeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_info_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_info_req extends Struct {
    public Ptr<sk_buff> msg;

    public Ptr<?> version_cb;

    public Ptr<?> version_cb_priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_info_version_type"
  )
  public enum devlink_info_version_type implements Enum<devlink_info_version_type>, TypedEnum<devlink_info_version_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_INFO_VERSION_TYPE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_INFO_VERSION_TYPE_NONE"
    )
    DEVLINK_INFO_VERSION_TYPE_NONE,

    /**
     * {@code DEVLINK_INFO_VERSION_TYPE_COMPONENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_INFO_VERSION_TYPE_COMPONENT"
    )
    DEVLINK_INFO_VERSION_TYPE_COMPONENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_reload_combination"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_reload_combination extends Struct {
    public devlink_reload_action action;

    public devlink_reload_limit limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_flash_component_lookup_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_flash_component_lookup_ctx extends Struct {
    public String lookup_name;

    public boolean lookup_name_found;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_port_fn_attr_cap"
  )
  public enum devlink_port_fn_attr_cap implements Enum<devlink_port_fn_attr_cap>, TypedEnum<devlink_port_fn_attr_cap, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PORT_FN_ATTR_CAP_ROCE_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PORT_FN_ATTR_CAP_ROCE_BIT"
    )
    DEVLINK_PORT_FN_ATTR_CAP_ROCE_BIT,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_CAP_MIGRATABLE_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PORT_FN_ATTR_CAP_MIGRATABLE_BIT"
    )
    DEVLINK_PORT_FN_ATTR_CAP_MIGRATABLE_BIT,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT"
    )
    DEVLINK_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT,

    /**
     * {@code DEVLINK_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT"
    )
    DEVLINK_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT,

    /**
     * {@code __DEVLINK_PORT_FN_ATTR_CAPS_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__DEVLINK_PORT_FN_ATTR_CAPS_MAX"
    )
    __DEVLINK_PORT_FN_ATTR_CAPS_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_sb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_sb extends Struct {
    public list_head list;

    public @Unsigned int index;

    public @Unsigned int size;

    public @Unsigned short ingress_pools_count;

    public @Unsigned short egress_pools_count;

    public @Unsigned short ingress_tc_count;

    public @Unsigned short egress_tc_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_match_type"
  )
  public enum devlink_dpipe_match_type implements Enum<devlink_dpipe_match_type>, TypedEnum<devlink_dpipe_match_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT"
    )
    DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_action_type"
  )
  public enum devlink_dpipe_action_type implements Enum<devlink_dpipe_action_type>, TypedEnum<devlink_dpipe_action_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY"
    )
    DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_field_ethernet_id"
  )
  public enum devlink_dpipe_field_ethernet_id implements Enum<devlink_dpipe_field_ethernet_id>, TypedEnum<devlink_dpipe_field_ethernet_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC"
    )
    DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_field_ipv4_id"
  )
  public enum devlink_dpipe_field_ipv4_id implements Enum<devlink_dpipe_field_ipv4_id>, TypedEnum<devlink_dpipe_field_ipv4_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_FIELD_IPV4_DST_IP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_FIELD_IPV4_DST_IP"
    )
    DEVLINK_DPIPE_FIELD_IPV4_DST_IP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_field_ipv6_id"
  )
  public enum devlink_dpipe_field_ipv6_id implements Enum<devlink_dpipe_field_ipv6_id>, TypedEnum<devlink_dpipe_field_ipv6_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_FIELD_IPV6_DST_IP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_FIELD_IPV6_DST_IP"
    )
    DEVLINK_DPIPE_FIELD_IPV6_DST_IP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_dpipe_header_id"
  )
  public enum devlink_dpipe_header_id implements Enum<devlink_dpipe_header_id>, TypedEnum<devlink_dpipe_header_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_DPIPE_HEADER_ETHERNET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_DPIPE_HEADER_ETHERNET"
    )
    DEVLINK_DPIPE_HEADER_ETHERNET,

    /**
     * {@code DEVLINK_DPIPE_HEADER_IPV4 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_DPIPE_HEADER_IPV4"
    )
    DEVLINK_DPIPE_HEADER_IPV4,

    /**
     * {@code DEVLINK_DPIPE_HEADER_IPV6 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_DPIPE_HEADER_IPV6"
    )
    DEVLINK_DPIPE_HEADER_IPV6
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_match"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_match extends Struct {
    public devlink_dpipe_match_type type;

    public @Unsigned int header_index;

    public Ptr<devlink_dpipe_header> header;

    public @Unsigned int field_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_action extends Struct {
    public devlink_dpipe_action_type type;

    public @Unsigned int header_index;

    public Ptr<devlink_dpipe_header> header;

    public @Unsigned int field_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_value extends Struct {
    @InlineUnion(63961)
    public Ptr<devlink_dpipe_action> action;

    @InlineUnion(63961)
    public Ptr<devlink_dpipe_match> match;

    public @Unsigned int mapping_value;

    public boolean mapping_valid;

    public @Unsigned int value_size;

    public Ptr<?> value;

    public Ptr<?> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_entry extends Struct {
    public @Unsigned long index;

    public Ptr<devlink_dpipe_value> match_values;

    public @Unsigned int match_values_count;

    public Ptr<devlink_dpipe_value> action_values;

    public @Unsigned int action_values_count;

    public @Unsigned long counter;

    public boolean counter_valid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_dump_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_dump_ctx extends Struct {
    public Ptr<genl_info> info;

    public devlink_command cmd;

    public Ptr<sk_buff> skb;

    public Ptr<nlattr> nest;

    public Ptr<?> hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_table extends Struct {
    public Ptr<?> priv;

    public list_head list;

    public String name;

    public boolean counters_enabled;

    public boolean counter_control_extern;

    public boolean resource_valid;

    public @Unsigned long resource_id;

    public @Unsigned long resource_units;

    public Ptr<devlink_dpipe_table_ops> table_ops;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_dpipe_table_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_dpipe_table_ops extends Struct {
    public Ptr<?> actions_dump;

    public Ptr<?> matches_dump;

    public Ptr<?> entries_dump;

    public Ptr<?> counters_set_update;

    public Ptr<?> size_get;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_resource_unit"
  )
  public enum devlink_resource_unit implements Enum<devlink_resource_unit>, TypedEnum<devlink_resource_unit, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_RESOURCE_UNIT_ENTRY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_RESOURCE_UNIT_ENTRY"
    )
    DEVLINK_RESOURCE_UNIT_ENTRY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_resource_size_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_resource_size_params extends Struct {
    public @Unsigned long size_min;

    public @Unsigned long size_max;

    public @Unsigned long size_granularity;

    public devlink_resource_unit unit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_resource"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_resource extends Struct {
    public String name;

    public @Unsigned long id;

    public @Unsigned long size;

    public @Unsigned long size_new;

    public boolean size_valid;

    public Ptr<devlink_resource> parent;

    public devlink_resource_size_params size_params;

    public list_head list;

    public list_head resource_list;

    public Ptr<?> occ_get;

    public Ptr<?> occ_get_priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_param_type"
  )
  public enum devlink_param_type implements Enum<devlink_param_type>, TypedEnum<devlink_param_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PARAM_TYPE_U8 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PARAM_TYPE_U8"
    )
    DEVLINK_PARAM_TYPE_U8,

    /**
     * {@code DEVLINK_PARAM_TYPE_U16 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PARAM_TYPE_U16"
    )
    DEVLINK_PARAM_TYPE_U16,

    /**
     * {@code DEVLINK_PARAM_TYPE_U32 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PARAM_TYPE_U32"
    )
    DEVLINK_PARAM_TYPE_U32,

    /**
     * {@code DEVLINK_PARAM_TYPE_U64 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_PARAM_TYPE_U64"
    )
    DEVLINK_PARAM_TYPE_U64,

    /**
     * {@code DEVLINK_PARAM_TYPE_STRING = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_PARAM_TYPE_STRING"
    )
    DEVLINK_PARAM_TYPE_STRING,

    /**
     * {@code DEVLINK_PARAM_TYPE_BOOL = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_PARAM_TYPE_BOOL"
    )
    DEVLINK_PARAM_TYPE_BOOL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_param extends Struct {
    public @Unsigned int id;

    public String name;

    public boolean generic;

    public devlink_param_type type;

    public @Unsigned long supported_cmodes;

    public Ptr<?> get;

    public Ptr<?> set;

    public Ptr<?> validate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_param_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_param_item extends Struct {
    public list_head list;

    public Ptr<devlink_param> param;

    public devlink_param_value driverinit_value;

    public boolean driverinit_value_valid;

    public devlink_param_value driverinit_value_new;

    public boolean driverinit_value_new_valid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_param_generic_id"
  )
  public enum devlink_param_generic_id implements Enum<devlink_param_generic_id>, TypedEnum<devlink_param_generic_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_INT_ERR_RESET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_PARAM_GENERIC_ID_INT_ERR_RESET"
    )
    DEVLINK_PARAM_GENERIC_ID_INT_ERR_RESET,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_MAX_MACS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_PARAM_GENERIC_ID_MAX_MACS"
    )
    DEVLINK_PARAM_GENERIC_ID_MAX_MACS,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_SRIOV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_SRIOV"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_SRIOV,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_REGION_SNAPSHOT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_PARAM_GENERIC_ID_REGION_SNAPSHOT"
    )
    DEVLINK_PARAM_GENERIC_ID_REGION_SNAPSHOT,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_IGNORE_ARI = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_PARAM_GENERIC_ID_IGNORE_ARI"
    )
    DEVLINK_PARAM_GENERIC_ID_IGNORE_ARI,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MAX"
    )
    DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MAX,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MIN = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MIN"
    )
    DEVLINK_PARAM_GENERIC_ID_MSIX_VEC_PER_PF_MIN,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_FW_LOAD_POLICY = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_PARAM_GENERIC_ID_FW_LOAD_POLICY"
    )
    DEVLINK_PARAM_GENERIC_ID_FW_LOAD_POLICY,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_RESET_DEV_ON_DRV_PROBE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DEVLINK_PARAM_GENERIC_ID_RESET_DEV_ON_DRV_PROBE"
    )
    DEVLINK_PARAM_GENERIC_ID_RESET_DEV_ON_DRV_PROBE,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_RDMA = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_RDMA"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_RDMA,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_VNET = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_VNET"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_VNET,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_IWARP = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_IWARP"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_IWARP,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE"
    )
    DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_EVENT_EQ_SIZE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DEVLINK_PARAM_GENERIC_ID_EVENT_EQ_SIZE"
    )
    DEVLINK_PARAM_GENERIC_ID_EVENT_EQ_SIZE,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_ENABLE_PHC = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DEVLINK_PARAM_GENERIC_ID_ENABLE_PHC"
    )
    DEVLINK_PARAM_GENERIC_ID_ENABLE_PHC,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_CLOCK_ID = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_PARAM_GENERIC_ID_CLOCK_ID"
    )
    DEVLINK_PARAM_GENERIC_ID_CLOCK_ID,

    /**
     * {@code __DEVLINK_PARAM_GENERIC_ID_MAX = 19}
     */
    @EnumMember(
        value = 19L,
        name = "__DEVLINK_PARAM_GENERIC_ID_MAX"
    )
    __DEVLINK_PARAM_GENERIC_ID_MAX,

    /**
     * {@code DEVLINK_PARAM_GENERIC_ID_MAX = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_PARAM_GENERIC_ID_MAX"
    )
    DEVLINK_PARAM_GENERIC_ID_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_region_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_region_ops extends Struct {
    public String name;

    public Ptr<?> destructor;

    public Ptr<?> snapshot;

    public Ptr<?> read;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_port_region_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_port_region_ops extends Struct {
    public String name;

    public Ptr<?> destructor;

    public Ptr<?> snapshot;

    public Ptr<?> read;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_region extends Struct {
    public Ptr<devlink> devlink;

    public Ptr<devlink_port> port;

    public list_head list;

    @InlineUnion(64058)
    public Ptr<devlink_region_ops> ops;

    @InlineUnion(64058)
    public Ptr<devlink_port_region_ops> port_ops;

    public mutex snapshot_lock;

    public list_head snapshot_list;

    public @Unsigned int max_snapshots;

    public @Unsigned int cur_snapshots;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_snapshot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_snapshot extends Struct {
    public list_head list;

    public Ptr<devlink_region> region;

    public Ptr<java.lang.Character> data;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_health_reporter_state"
  )
  public enum devlink_health_reporter_state implements Enum<devlink_health_reporter_state>, TypedEnum<devlink_health_reporter_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_HEALTH_REPORTER_STATE_HEALTHY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_HEALTH_REPORTER_STATE_HEALTHY"
    )
    DEVLINK_HEALTH_REPORTER_STATE_HEALTHY,

    /**
     * {@code DEVLINK_HEALTH_REPORTER_STATE_ERROR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_HEALTH_REPORTER_STATE_ERROR"
    )
    DEVLINK_HEALTH_REPORTER_STATE_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_health_reporter_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_health_reporter_ops extends Struct {
    public String name;

    public Ptr<?> recover;

    public Ptr<?> dump;

    public Ptr<?> diagnose;

    public Ptr<?> test;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_health_reporter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_health_reporter extends Struct {
    public list_head list;

    public Ptr<?> priv;

    public Ptr<devlink_health_reporter_ops> ops;

    public Ptr<devlink> devlink;

    public Ptr<devlink_port> devlink_port;

    public Ptr<devlink_fmsg> dump_fmsg;

    public @Unsigned long graceful_period;

    public boolean auto_recover;

    public boolean auto_dump;

    public char health_state;

    public @Unsigned long dump_ts;

    public @Unsigned long dump_real_ts;

    public @Unsigned long error_count;

    public @Unsigned long recovery_count;

    public @Unsigned long last_recovery_ts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_fmsg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_fmsg extends Struct {
    public list_head item_list;

    public int err;

    public boolean putting_binary;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_fmsg_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_fmsg_item extends Struct {
    public list_head list;

    public int attrtype;

    public char nla_type;

    public @Unsigned short len;

    public int @Size(0) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_trap_generic_id"
  )
  public enum devlink_trap_generic_id implements Enum<devlink_trap_generic_id>, TypedEnum<devlink_trap_generic_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_SMAC_MC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_TRAP_GENERIC_ID_SMAC_MC"
    )
    DEVLINK_TRAP_GENERIC_ID_SMAC_MC,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_VLAN_TAG_MISMATCH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_TRAP_GENERIC_ID_VLAN_TAG_MISMATCH"
    )
    DEVLINK_TRAP_GENERIC_ID_VLAN_TAG_MISMATCH,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_INGRESS_VLAN_FILTER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_TRAP_GENERIC_ID_INGRESS_VLAN_FILTER"
    )
    DEVLINK_TRAP_GENERIC_ID_INGRESS_VLAN_FILTER,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_INGRESS_STP_FILTER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_TRAP_GENERIC_ID_INGRESS_STP_FILTER"
    )
    DEVLINK_TRAP_GENERIC_ID_INGRESS_STP_FILTER,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_EMPTY_TX_LIST = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_TRAP_GENERIC_ID_EMPTY_TX_LIST"
    )
    DEVLINK_TRAP_GENERIC_ID_EMPTY_TX_LIST,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_PORT_LOOPBACK_FILTER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_TRAP_GENERIC_ID_PORT_LOOPBACK_FILTER"
    )
    DEVLINK_TRAP_GENERIC_ID_PORT_LOOPBACK_FILTER,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_ROUTE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_ROUTE"
    )
    DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_ROUTE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_TTL_ERROR = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_TRAP_GENERIC_ID_TTL_ERROR"
    )
    DEVLINK_TRAP_GENERIC_ID_TTL_ERROR,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_TAIL_DROP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DEVLINK_TRAP_GENERIC_ID_TAIL_DROP"
    )
    DEVLINK_TRAP_GENERIC_ID_TAIL_DROP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_NON_IP_PACKET = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DEVLINK_TRAP_GENERIC_ID_NON_IP_PACKET"
    )
    DEVLINK_TRAP_GENERIC_ID_NON_IP_PACKET,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_UC_DIP_MC_DMAC = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_TRAP_GENERIC_ID_UC_DIP_MC_DMAC"
    )
    DEVLINK_TRAP_GENERIC_ID_UC_DIP_MC_DMAC,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_DIP_LB = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_TRAP_GENERIC_ID_DIP_LB"
    )
    DEVLINK_TRAP_GENERIC_ID_DIP_LB,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_SIP_MC = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DEVLINK_TRAP_GENERIC_ID_SIP_MC"
    )
    DEVLINK_TRAP_GENERIC_ID_SIP_MC,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_SIP_LB = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DEVLINK_TRAP_GENERIC_ID_SIP_LB"
    )
    DEVLINK_TRAP_GENERIC_ID_SIP_LB,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_CORRUPTED_IP_HDR = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DEVLINK_TRAP_GENERIC_ID_CORRUPTED_IP_HDR"
    )
    DEVLINK_TRAP_GENERIC_ID_CORRUPTED_IP_HDR,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_SIP_BC = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_SIP_BC"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_SIP_BC,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_RESERVED_SCOPE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_RESERVED_SCOPE"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_RESERVED_SCOPE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_MC_DIP_INTERFACE_LOCAL_SCOPE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MTU_ERROR = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_TRAP_GENERIC_ID_MTU_ERROR"
    )
    DEVLINK_TRAP_GENERIC_ID_MTU_ERROR,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH = 19}
     */
    @EnumMember(
        value = 19L,
        name = "DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH"
    )
    DEVLINK_TRAP_GENERIC_ID_UNRESOLVED_NEIGH,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_RPF = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DEVLINK_TRAP_GENERIC_ID_RPF"
    )
    DEVLINK_TRAP_GENERIC_ID_RPF,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_REJECT_ROUTE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "DEVLINK_TRAP_GENERIC_ID_REJECT_ROUTE"
    )
    DEVLINK_TRAP_GENERIC_ID_REJECT_ROUTE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_LPM_UNICAST_MISS = 22}
     */
    @EnumMember(
        value = 22L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_LPM_UNICAST_MISS"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_LPM_UNICAST_MISS,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_LPM_UNICAST_MISS = 23}
     */
    @EnumMember(
        value = 23L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_LPM_UNICAST_MISS"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_LPM_UNICAST_MISS,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_NON_ROUTABLE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "DEVLINK_TRAP_GENERIC_ID_NON_ROUTABLE"
    )
    DEVLINK_TRAP_GENERIC_ID_NON_ROUTABLE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR = 25}
     */
    @EnumMember(
        value = 25L,
        name = "DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR"
    )
    DEVLINK_TRAP_GENERIC_ID_DECAP_ERROR,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_OVERLAY_SMAC_MC = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DEVLINK_TRAP_GENERIC_ID_OVERLAY_SMAC_MC"
    )
    DEVLINK_TRAP_GENERIC_ID_OVERLAY_SMAC_MC,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_INGRESS_FLOW_ACTION_DROP = 27}
     */
    @EnumMember(
        value = 27L,
        name = "DEVLINK_TRAP_GENERIC_ID_INGRESS_FLOW_ACTION_DROP"
    )
    DEVLINK_TRAP_GENERIC_ID_INGRESS_FLOW_ACTION_DROP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_EGRESS_FLOW_ACTION_DROP = 28}
     */
    @EnumMember(
        value = 28L,
        name = "DEVLINK_TRAP_GENERIC_ID_EGRESS_FLOW_ACTION_DROP"
    )
    DEVLINK_TRAP_GENERIC_ID_EGRESS_FLOW_ACTION_DROP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_STP = 29}
     */
    @EnumMember(
        value = 29L,
        name = "DEVLINK_TRAP_GENERIC_ID_STP"
    )
    DEVLINK_TRAP_GENERIC_ID_STP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_LACP = 30}
     */
    @EnumMember(
        value = 30L,
        name = "DEVLINK_TRAP_GENERIC_ID_LACP"
    )
    DEVLINK_TRAP_GENERIC_ID_LACP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_LLDP = 31}
     */
    @EnumMember(
        value = 31L,
        name = "DEVLINK_TRAP_GENERIC_ID_LLDP"
    )
    DEVLINK_TRAP_GENERIC_ID_LLDP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IGMP_QUERY = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DEVLINK_TRAP_GENERIC_ID_IGMP_QUERY"
    )
    DEVLINK_TRAP_GENERIC_ID_IGMP_QUERY,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IGMP_V1_REPORT = 33}
     */
    @EnumMember(
        value = 33L,
        name = "DEVLINK_TRAP_GENERIC_ID_IGMP_V1_REPORT"
    )
    DEVLINK_TRAP_GENERIC_ID_IGMP_V1_REPORT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IGMP_V2_REPORT = 34}
     */
    @EnumMember(
        value = 34L,
        name = "DEVLINK_TRAP_GENERIC_ID_IGMP_V2_REPORT"
    )
    DEVLINK_TRAP_GENERIC_ID_IGMP_V2_REPORT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IGMP_V3_REPORT = 35}
     */
    @EnumMember(
        value = 35L,
        name = "DEVLINK_TRAP_GENERIC_ID_IGMP_V3_REPORT"
    )
    DEVLINK_TRAP_GENERIC_ID_IGMP_V3_REPORT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IGMP_V2_LEAVE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "DEVLINK_TRAP_GENERIC_ID_IGMP_V2_LEAVE"
    )
    DEVLINK_TRAP_GENERIC_ID_IGMP_V2_LEAVE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MLD_QUERY = 37}
     */
    @EnumMember(
        value = 37L,
        name = "DEVLINK_TRAP_GENERIC_ID_MLD_QUERY"
    )
    DEVLINK_TRAP_GENERIC_ID_MLD_QUERY,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MLD_V1_REPORT = 38}
     */
    @EnumMember(
        value = 38L,
        name = "DEVLINK_TRAP_GENERIC_ID_MLD_V1_REPORT"
    )
    DEVLINK_TRAP_GENERIC_ID_MLD_V1_REPORT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MLD_V2_REPORT = 39}
     */
    @EnumMember(
        value = 39L,
        name = "DEVLINK_TRAP_GENERIC_ID_MLD_V2_REPORT"
    )
    DEVLINK_TRAP_GENERIC_ID_MLD_V2_REPORT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MLD_V1_DONE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "DEVLINK_TRAP_GENERIC_ID_MLD_V1_DONE"
    )
    DEVLINK_TRAP_GENERIC_ID_MLD_V1_DONE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_DHCP = 41}
     */
    @EnumMember(
        value = 41L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_DHCP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_DHCP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_DHCP = 42}
     */
    @EnumMember(
        value = 42L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_DHCP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_DHCP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_ARP_REQUEST = 43}
     */
    @EnumMember(
        value = 43L,
        name = "DEVLINK_TRAP_GENERIC_ID_ARP_REQUEST"
    )
    DEVLINK_TRAP_GENERIC_ID_ARP_REQUEST,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_ARP_RESPONSE = 44}
     */
    @EnumMember(
        value = 44L,
        name = "DEVLINK_TRAP_GENERIC_ID_ARP_RESPONSE"
    )
    DEVLINK_TRAP_GENERIC_ID_ARP_RESPONSE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_ARP_OVERLAY = 45}
     */
    @EnumMember(
        value = 45L,
        name = "DEVLINK_TRAP_GENERIC_ID_ARP_OVERLAY"
    )
    DEVLINK_TRAP_GENERIC_ID_ARP_OVERLAY,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_SOLICIT = 46}
     */
    @EnumMember(
        value = 46L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_SOLICIT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_SOLICIT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_ADVERT = 47}
     */
    @EnumMember(
        value = 47L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_ADVERT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_NEIGH_ADVERT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_BFD = 48}
     */
    @EnumMember(
        value = 48L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_BFD"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_BFD,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_BFD = 49}
     */
    @EnumMember(
        value = 49L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_BFD"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_BFD,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_OSPF = 50}
     */
    @EnumMember(
        value = 50L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_OSPF"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_OSPF,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_OSPF = 51}
     */
    @EnumMember(
        value = 51L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_OSPF"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_OSPF,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_BGP = 52}
     */
    @EnumMember(
        value = 52L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_BGP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_BGP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_BGP = 53}
     */
    @EnumMember(
        value = 53L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_BGP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_BGP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_VRRP = 54}
     */
    @EnumMember(
        value = 54L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_VRRP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_VRRP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_VRRP = 55}
     */
    @EnumMember(
        value = 55L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_VRRP"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_VRRP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_PIM = 56}
     */
    @EnumMember(
        value = 56L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_PIM"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_PIM,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_PIM = 57}
     */
    @EnumMember(
        value = 57L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_PIM"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_PIM,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_UC_LB = 58}
     */
    @EnumMember(
        value = 58L,
        name = "DEVLINK_TRAP_GENERIC_ID_UC_LB"
    )
    DEVLINK_TRAP_GENERIC_ID_UC_LB,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_LOCAL_ROUTE = 59}
     */
    @EnumMember(
        value = 59L,
        name = "DEVLINK_TRAP_GENERIC_ID_LOCAL_ROUTE"
    )
    DEVLINK_TRAP_GENERIC_ID_LOCAL_ROUTE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_EXTERNAL_ROUTE = 60}
     */
    @EnumMember(
        value = 60L,
        name = "DEVLINK_TRAP_GENERIC_ID_EXTERNAL_ROUTE"
    )
    DEVLINK_TRAP_GENERIC_ID_EXTERNAL_ROUTE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_UC_DIP_LINK_LOCAL_SCOPE = 61}
     */
    @EnumMember(
        value = 61L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_UC_DIP_LINK_LOCAL_SCOPE"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_UC_DIP_LINK_LOCAL_SCOPE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_NODES = 62}
     */
    @EnumMember(
        value = 62L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_NODES"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_NODES,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_ROUTERS = 63}
     */
    @EnumMember(
        value = 63L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_ROUTERS"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_DIP_ALL_ROUTERS,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_SOLICIT = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_SOLICIT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_SOLICIT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ADVERT = 65}
     */
    @EnumMember(
        value = 65L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ADVERT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ADVERT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_REDIRECT = 66}
     */
    @EnumMember(
        value = 66L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_REDIRECT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_REDIRECT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV4_ROUTER_ALERT = 67}
     */
    @EnumMember(
        value = 67L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV4_ROUTER_ALERT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV4_ROUTER_ALERT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ALERT = 68}
     */
    @EnumMember(
        value = 68L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ALERT"
    )
    DEVLINK_TRAP_GENERIC_ID_IPV6_ROUTER_ALERT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_PTP_EVENT = 69}
     */
    @EnumMember(
        value = 69L,
        name = "DEVLINK_TRAP_GENERIC_ID_PTP_EVENT"
    )
    DEVLINK_TRAP_GENERIC_ID_PTP_EVENT,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_PTP_GENERAL = 70}
     */
    @EnumMember(
        value = 70L,
        name = "DEVLINK_TRAP_GENERIC_ID_PTP_GENERAL"
    )
    DEVLINK_TRAP_GENERIC_ID_PTP_GENERAL,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_SAMPLE = 71}
     */
    @EnumMember(
        value = 71L,
        name = "DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_SAMPLE"
    )
    DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_SAMPLE,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_TRAP = 72}
     */
    @EnumMember(
        value = 72L,
        name = "DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_TRAP"
    )
    DEVLINK_TRAP_GENERIC_ID_FLOW_ACTION_TRAP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_EARLY_DROP = 73}
     */
    @EnumMember(
        value = 73L,
        name = "DEVLINK_TRAP_GENERIC_ID_EARLY_DROP"
    )
    DEVLINK_TRAP_GENERIC_ID_EARLY_DROP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_VXLAN_PARSING = 74}
     */
    @EnumMember(
        value = 74L,
        name = "DEVLINK_TRAP_GENERIC_ID_VXLAN_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_VXLAN_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_LLC_SNAP_PARSING = 75}
     */
    @EnumMember(
        value = 75L,
        name = "DEVLINK_TRAP_GENERIC_ID_LLC_SNAP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_LLC_SNAP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_VLAN_PARSING = 76}
     */
    @EnumMember(
        value = 76L,
        name = "DEVLINK_TRAP_GENERIC_ID_VLAN_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_VLAN_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_PPPOE_PPP_PARSING = 77}
     */
    @EnumMember(
        value = 77L,
        name = "DEVLINK_TRAP_GENERIC_ID_PPPOE_PPP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_PPPOE_PPP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MPLS_PARSING = 78}
     */
    @EnumMember(
        value = 78L,
        name = "DEVLINK_TRAP_GENERIC_ID_MPLS_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_MPLS_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_ARP_PARSING = 79}
     */
    @EnumMember(
        value = 79L,
        name = "DEVLINK_TRAP_GENERIC_ID_ARP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_ARP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IP_1_PARSING = 80}
     */
    @EnumMember(
        value = 80L,
        name = "DEVLINK_TRAP_GENERIC_ID_IP_1_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_IP_1_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IP_N_PARSING = 81}
     */
    @EnumMember(
        value = 81L,
        name = "DEVLINK_TRAP_GENERIC_ID_IP_N_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_IP_N_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_GRE_PARSING = 82}
     */
    @EnumMember(
        value = 82L,
        name = "DEVLINK_TRAP_GENERIC_ID_GRE_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_GRE_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_UDP_PARSING = 83}
     */
    @EnumMember(
        value = 83L,
        name = "DEVLINK_TRAP_GENERIC_ID_UDP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_UDP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_TCP_PARSING = 84}
     */
    @EnumMember(
        value = 84L,
        name = "DEVLINK_TRAP_GENERIC_ID_TCP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_TCP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_IPSEC_PARSING = 85}
     */
    @EnumMember(
        value = 85L,
        name = "DEVLINK_TRAP_GENERIC_ID_IPSEC_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_IPSEC_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_SCTP_PARSING = 86}
     */
    @EnumMember(
        value = 86L,
        name = "DEVLINK_TRAP_GENERIC_ID_SCTP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_SCTP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_DCCP_PARSING = 87}
     */
    @EnumMember(
        value = 87L,
        name = "DEVLINK_TRAP_GENERIC_ID_DCCP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_DCCP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_GTP_PARSING = 88}
     */
    @EnumMember(
        value = 88L,
        name = "DEVLINK_TRAP_GENERIC_ID_GTP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_GTP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_ESP_PARSING = 89}
     */
    @EnumMember(
        value = 89L,
        name = "DEVLINK_TRAP_GENERIC_ID_ESP_PARSING"
    )
    DEVLINK_TRAP_GENERIC_ID_ESP_PARSING,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_NEXTHOP = 90}
     */
    @EnumMember(
        value = 90L,
        name = "DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_NEXTHOP"
    )
    DEVLINK_TRAP_GENERIC_ID_BLACKHOLE_NEXTHOP,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER = 91}
     */
    @EnumMember(
        value = 91L,
        name = "DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER"
    )
    DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_EAPOL = 92}
     */
    @EnumMember(
        value = 92L,
        name = "DEVLINK_TRAP_GENERIC_ID_EAPOL"
    )
    DEVLINK_TRAP_GENERIC_ID_EAPOL,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_LOCKED_PORT = 93}
     */
    @EnumMember(
        value = 93L,
        name = "DEVLINK_TRAP_GENERIC_ID_LOCKED_PORT"
    )
    DEVLINK_TRAP_GENERIC_ID_LOCKED_PORT,

    /**
     * {@code __DEVLINK_TRAP_GENERIC_ID_MAX = 94}
     */
    @EnumMember(
        value = 94L,
        name = "__DEVLINK_TRAP_GENERIC_ID_MAX"
    )
    __DEVLINK_TRAP_GENERIC_ID_MAX,

    /**
     * {@code DEVLINK_TRAP_GENERIC_ID_MAX = 93}
     */
    @EnumMember(
        value = 93L,
        name = "DEVLINK_TRAP_GENERIC_ID_MAX"
    )
    DEVLINK_TRAP_GENERIC_ID_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_trap_group_generic_id"
  )
  public enum devlink_trap_group_generic_id implements Enum<devlink_trap_group_generic_id>, TypedEnum<devlink_trap_group_generic_id, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_L2_DROPS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_L2_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_L2_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_L3_DROPS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_L3_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_L3_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_L3_EXCEPTIONS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_L3_EXCEPTIONS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_L3_EXCEPTIONS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_BUFFER_DROPS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_BUFFER_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_BUFFER_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_TUNNEL_DROPS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_TUNNEL_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_TUNNEL_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_DROPS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_STP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_STP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_STP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_LACP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_LACP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_LACP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_LLDP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_LLDP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_LLDP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_MC_SNOOPING = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_MC_SNOOPING"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_MC_SNOOPING,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_DHCP = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_DHCP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_DHCP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_NEIGH_DISCOVERY = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_NEIGH_DISCOVERY"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_NEIGH_DISCOVERY,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_BFD = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_BFD"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_BFD,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_OSPF = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_OSPF"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_OSPF,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_BGP = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_BGP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_BGP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_VRRP = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_VRRP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_VRRP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_PIM = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_PIM"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_PIM,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_UC_LB = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_UC_LB"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_UC_LB,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_LOCAL_DELIVERY = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_LOCAL_DELIVERY"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_LOCAL_DELIVERY,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_EXTERNAL_DELIVERY = 19}
     */
    @EnumMember(
        value = 19L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_EXTERNAL_DELIVERY"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_EXTERNAL_DELIVERY,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_IPV6 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_IPV6"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_IPV6,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_EVENT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_EVENT"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_EVENT,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_GENERAL = 22}
     */
    @EnumMember(
        value = 22L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_GENERAL"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_PTP_GENERAL,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_SAMPLE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_SAMPLE"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_SAMPLE,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_TRAP = 24}
     */
    @EnumMember(
        value = 24L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_TRAP"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_ACL_TRAP,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_PARSER_ERROR_DROPS = 25}
     */
    @EnumMember(
        value = 25L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_PARSER_ERROR_DROPS"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_PARSER_ERROR_DROPS,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_EAPOL = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_EAPOL"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_EAPOL,

    /**
     * {@code __DEVLINK_TRAP_GROUP_GENERIC_ID_MAX = 27}
     */
    @EnumMember(
        value = 27L,
        name = "__DEVLINK_TRAP_GROUP_GENERIC_ID_MAX"
    )
    __DEVLINK_TRAP_GROUP_GENERIC_ID_MAX,

    /**
     * {@code DEVLINK_TRAP_GROUP_GENERIC_ID_MAX = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DEVLINK_TRAP_GROUP_GENERIC_ID_MAX"
    )
    DEVLINK_TRAP_GROUP_GENERIC_ID_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_stats extends Struct {
    public u64_stats_t rx_bytes;

    public u64_stats_t rx_packets;

    public u64_stats_sync syncp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_policer_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_policer_item extends Struct {
    public Ptr<devlink_trap_policer> policer;

    public @Unsigned long rate;

    public @Unsigned long burst;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_group_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_group_item extends Struct {
    public Ptr<devlink_trap_group> group;

    public Ptr<devlink_trap_policer_item> policer_item;

    public list_head list;

    public Ptr<devlink_stats> stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_trap_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_trap_item extends Struct {
    public Ptr<devlink_trap> trap;

    public Ptr<devlink_trap_group_item> group_item;

    public list_head list;

    public devlink_trap_action action;

    public Ptr<devlink_stats> stats;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devlink_linecard_state"
  )
  public enum devlink_linecard_state implements Enum<devlink_linecard_state>, TypedEnum<devlink_linecard_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVLINK_LINECARD_STATE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVLINK_LINECARD_STATE_UNSPEC"
    )
    DEVLINK_LINECARD_STATE_UNSPEC,

    /**
     * {@code DEVLINK_LINECARD_STATE_UNPROVISIONED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVLINK_LINECARD_STATE_UNPROVISIONED"
    )
    DEVLINK_LINECARD_STATE_UNPROVISIONED,

    /**
     * {@code DEVLINK_LINECARD_STATE_UNPROVISIONING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVLINK_LINECARD_STATE_UNPROVISIONING"
    )
    DEVLINK_LINECARD_STATE_UNPROVISIONING,

    /**
     * {@code DEVLINK_LINECARD_STATE_PROVISIONING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVLINK_LINECARD_STATE_PROVISIONING"
    )
    DEVLINK_LINECARD_STATE_PROVISIONING,

    /**
     * {@code DEVLINK_LINECARD_STATE_PROVISIONING_FAILED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DEVLINK_LINECARD_STATE_PROVISIONING_FAILED"
    )
    DEVLINK_LINECARD_STATE_PROVISIONING_FAILED,

    /**
     * {@code DEVLINK_LINECARD_STATE_PROVISIONED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DEVLINK_LINECARD_STATE_PROVISIONED"
    )
    DEVLINK_LINECARD_STATE_PROVISIONED,

    /**
     * {@code DEVLINK_LINECARD_STATE_ACTIVE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_LINECARD_STATE_ACTIVE"
    )
    DEVLINK_LINECARD_STATE_ACTIVE,

    /**
     * {@code __DEVLINK_LINECARD_STATE_MAX = 7}
     */
    @EnumMember(
        value = 7L,
        name = "__DEVLINK_LINECARD_STATE_MAX"
    )
    __DEVLINK_LINECARD_STATE_MAX,

    /**
     * {@code DEVLINK_LINECARD_STATE_MAX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DEVLINK_LINECARD_STATE_MAX"
    )
    DEVLINK_LINECARD_STATE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_linecard"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_linecard extends Struct {
    public list_head list;

    public Ptr<devlink> devlink;

    public @Unsigned int index;

    public Ptr<devlink_linecard_ops> ops;

    public Ptr<?> priv;

    public devlink_linecard_state state;

    public mutex state_lock;

    public String type;

    public Ptr<devlink_linecard_type> types;

    public @Unsigned int types_count;

    public @Unsigned int rel_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_linecard_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_linecard_ops extends Struct {
    public Ptr<?> provision;

    public Ptr<?> unprovision;

    public Ptr<?> same_provision;

    public Ptr<?> types_count;

    public Ptr<?> types_get;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devlink_linecard_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devlink_linecard_type extends Struct {
    public String type;

    public Ptr<?> priv;
  }
}
